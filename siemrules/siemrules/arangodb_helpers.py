import contextlib
from datetime import UTC, datetime
import json
from pathlib import Path
import arango.exceptions
from pytz import utc
from rest_framework import request
from django.http import HttpRequest, HttpResponse
# from django.conf import settings
from siemrules import settings
import typing

from siemrules.siemrules.utils import TLP_LEVEL_STIX_ID_MAPPING
from siemrules.worker.tasks import upload_to_arango

if typing.TYPE_CHECKING:
    from siemrules import settings

from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings
from rest_framework.exceptions import NotFound, ParseError
from rest_framework.response import Response
from stix2.utils import format_datetime



RULES_SORT_FIELDS = [
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
]

def fix_report_id(report_id: str):
    if report_id.startswith('report--'):
        return report_id
    return "report--"+report_id

def get_rules(request, paginate=True, all_versions=False, nokeep=True, rule_type="base"):
    helper = ArangoDBHelper(settings.VIEW_NAME, request, result_key="rules")
    binds = {}
    filters = []

    version_filter = 'doc._is_latest'
    if version := helper.query.get('version'):
        binds['version'] = version
        version_filter = 'doc.modified == @version'
    if all_versions:
        version_filter = 'TRUE'



    report_ids = helper.query_as_array('report_id')
    if file_ids := helper.query_as_array('file_id'):
        report_ids.extend(map(lambda id: fix_report_id(id), file_ids))

    if report_ids:
        binds['report_ids'] = report_ids
        filters.append(
            "FILTER doc._stixify_report_id IN @report_ids"
        )

    if value := helper.query_as_array('indicator_id'):
        binds['indicator_ids'] = value
        filters.append(
            "FILTER doc.id in @indicator_ids"
        )



    if name := helper.query.get('name', '').lower():
        binds['name'] = name
        filters.append("FILTER CONTAINS(LOWER(doc.name), @name)")

    if tlp_level := helper.query.get('tlp_level'):
        binds['tlp_level_stix_id'] = TLP_LEVEL_STIX_ID_MAPPING.get(tlp_level)
        filters.append('FILTER @tlp_level_stix_id IN doc.object_marking_refs')

    if values := helper.query_as_array('created_by_ref'):
        binds['created_by_ref'] = values
        filters.append('FILTER doc.created_by_ref IN @created_by_ref')
        
    if q := helper.query_as_array('attack_id'):
        binds['attack_ids'] = [r.upper() for r in q]
        filters.append('''
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name == 'mitre-attack' AND CURRENT.external_id IN @attack_ids]
            ''')
        
    if q := helper.query_as_array('cve_id'):
        binds['cve_ids'] = [r.upper() for r in q]
        filters.append('''
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name == 'cve' AND CURRENT.external_id IN @cve_ids]
            ''')
        
    

    filters.append('FILTER STARTS_WITH(doc.labels[0], "siemrules.correlation-rule") == @show_correlation_rules')
    binds.update(show_correlation_rules=rule_type == 'correlation')


    query = """

FOR doc IN siemrules_vertex_collection
FILTER doc.type == 'indicator' AND #version

@filters
@sort_stmt
#LIMIT
RETURN KEEP(doc, KEYS(doc, #NOKEEP))
""" \
        .replace('#version', version_filter) \
        .replace(
            "@filters", "\n".join(filters)
        ) \
        .replace('#NOKEEP', str(nokeep))\
        .replace(
            "@sort_stmt",
            helper.get_sort_stmt(
                RULES_SORT_FIELDS,
            ),
        )
    limit_str = ''
    if paginate:
        limit_str = 'LIMIT @offset, @count'
    query = query.replace('#LIMIT', limit_str)
    # return HttpResponse(f"{query}\n\n//"+json.dumps(binds))
    return helper.execute_query(query, bind_vars=binds, paginate=paginate)

def get_single_rule(indicator_id, rule_type="base", version=None):
    r = request.Request(HttpRequest())
    r.query_params.update(indicator_id=indicator_id, version=version)
    rules = get_rules(r, paginate=False, rule_type=rule_type)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    return Response(rules[0])

def get_single_rule_versions(indicator_id, rule_type="base"):
    r = request.Request(HttpRequest())
    r.query_params.update(indicator_id=indicator_id)
    rules = get_rules(r, paginate=False, all_versions=True, rule_type=rule_type)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    return Response(sorted([rule['modified'] for rule in rules], reverse=True))

def get_objects_for_rule(indicator_id, version=None, rule_type="base"):
    r = request.Request(HttpRequest())
    r.query_params.update(indicator_id=indicator_id, version=version)
    helper = ArangoDBHelper(settings.VIEW_NAME, r)
    rules = get_rules(r, paginate=False, nokeep=False, rule_type=rule_type)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    rule = rules[0]
    query = '''
    LET rel_ids = (FOR rel IN siemrules_edge_collection FILTER rel._from == @rule_key OR rel._to == @rule_key RETURN [rel._from, rel._to, rel._id])
    LET obj_ids = FLATTEN([@rule_key, rel_ids], 3)
    FOR doc IN @@view
    FILTER doc._id IN obj_ids
    LIMIT @offset, @count
    RETURN KEEP(doc, KEYS(doc, TRUE))
    '''
    return helper.execute_query(query, bind_vars={'rule_key': rule['_id'], '@view': settings.VIEW_NAME})


def get_objects_by_id(indicator_id):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    objects = helper.execute_query('''
            FOR doc IN siemrules_vertex_collection
            FILTER doc.type IN ['report', 'indicator']
            FILTER doc.id == @stix_id OR (doc.type == 'report' AND @stix_id IN doc.object_refs)
            FILTER doc._is_latest == TRUE
            RETURN doc
    ''', bind_vars=dict(stix_id=indicator_id), paginate=False)
    report = obj = None
    with contextlib.suppress(IndexError):
        report = [obj for obj in objects if obj['type'] == 'report'][0]
        obj = [obj for obj in objects if obj['id'] == indicator_id][0]
    if not obj:
        raise NotFound(f"no rule with id `{indicator_id}`")
    if not report:
        raise ParseError(f"cannot find report associated with rule `{indicator_id}`")


    rels = helper.execute_query('''
            FOR doc IN siemrules_edge_collection
            FILTER doc._from == @stix_id_key
            RETURN doc
    ''', bind_vars=dict(stix_id_key=obj['_id']), paginate=False)

    all_objs = [obj] + rels
    return report, obj, all_objs

from stix2arango.stix2arango import Stix2Arango

def make_upload(report_id, bundle):
    file_id = report_id.removeprefix('report--')
    s2a = Stix2Arango(
        file=None,
        database=settings.ARANGODB_DATABASE,
        collection=settings.ARANGODB_COLLECTION,
        stix2arango_note=f"siemrules-file--{file_id}",
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        ignore_embedded_relationships=False,
        )
    s2a.arangodb_extra_data = dict(_stixify_report_id=report_id)
    s2a.run(data=bundle)


def modify_rule(indicator_id, old_modified, new_modified, new_objects):
    report, obj, all_objs = get_objects_by_id(indicator_id)
    object_refs: list = report['object_refs'] + [obj['id'] for obj in new_objects]
    for ref in all_objs:
        try:
            object_refs.remove(ref['id'])
        except Exception as e:
            print(e)
            pass

    if obj['modified'] != old_modified:
        raise Exception('object modified on db after modification job started')
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    # helper.execute_query('''
    #         LET vertex_deletions = (
    #                     FOR doc IN siemrules_vertex_collection
    #                     FILTER doc._key IN @keys
    #                     UPDATE doc WITH {_is_latest: FALSE} IN siemrules_vertex_collection
    #                     RETURN doc.id
    #         )

    #         LET edge_deletions = (
    #                     FOR doc IN siemrules_edge_collection
    #                     FILTER doc._key IN @keys
    #                     UPDATE doc WITH {_is_latest: FALSE} IN siemrules_edge_collection
    #                     RETURN doc.id
    #         )
    #         RETURN {vertex_deletions, edge_deletions}
            
    # ''', bind_vars=dict(keys=[obj['_key'] for obj in all_objs]), paginate=False)

    make_upload(report['id'], {'objects': new_objects, 'type': 'bundle', 'id': f'bundle--{report["id"][8:]}'})

    helper.execute_query('UPDATE {_key: @report_key} WITH @report_update IN siemrules_vertex_collection', 
                        bind_vars=dict(report_key=report['_key'], report_update=dict(object_refs=object_refs, modified=new_modified)), paginate=False)
    

    
def delete_rule(indicator_id, rule_type="base", rule_date='', delete=True):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    new_modified = format_datetime(datetime.now(UTC))
    objects = helper.execute_query('''
            FOR doc IN siemrules_vertex_collection
            FILTER doc.type IN ['report', 'indicator']
            FILTER doc.id == @stix_id OR (doc.type == 'report' AND @stix_id IN doc.object_refs)
            RETURN KEEP(doc, "id", "_id", "_key", "object_refs", "type", "modified")
    ''', bind_vars=dict(stix_id=indicator_id), paginate=False)

    report = None
    rules = []
    revert_key_id = None
    with contextlib.suppress(IndexError):
        for obj in objects:
            if obj['type'] == 'report':
                report = obj
                continue
            if obj['id'] == indicator_id:
                rules.append(obj)
                if obj['modified'] == rule_date:
                    revert_key_id = obj['_id']

    if not rules:
        raise NotFound(f"no rules with id `{indicator_id}`")
    
    if rule_type == 'base' and not report:
        raise ParseError(f"cannot find report associated with rule `{indicator_id}`")

    rels = helper.execute_query('''
            FOR doc IN siemrules_edge_collection
            FILTER doc._from IN @stix_id_keys
            RETURN KEEP(doc, "id", "_id", "_from", "_to", "_key")
    ''', bind_vars=dict(stix_id_keys=[obj['_id'] for obj in rules]), paginate=False)

    if  rule_type == 'base' and delete:
        report['object_refs'].remove(indicator_id)
        for obj in rules:
            with contextlib.suppress(Exception):
                report['object_refs'].remove(obj['id'])

        helper.execute_query('UPDATE {_key: @report_key} WITH @report_update IN siemrules_vertex_collection', 
                            bind_vars=dict(report_key=report['_key'], report_update=dict(object_refs=report['object_refs'], modified=new_modified)), paginate=False)

    if delete:
        helper.execute_query('''
                LET vertex_deletions = (
                            FOR doc IN siemrules_vertex_collection
                            FILTER doc._key IN @keys
                            REMOVE doc IN siemrules_vertex_collection
                            RETURN doc.id
                )

                LET edge_deletions = (
                            FOR doc IN siemrules_edge_collection
                            FILTER doc._key IN @keys
                            REMOVE doc  IN siemrules_edge_collection
                            RETURN doc.id
                )
                RETURN {vertex_deletions, edge_deletions}
                
        ''', bind_vars=dict(keys=[obj['_key'] for obj in rules+rels]), paginate=False)
    else: #revert
        if not revert_key_id:
            raise ParseError(f"cannot find rule `{indicator_id}` @ {rule_date}")

        helper.execute_query('''
                LET vertex_deletions = (
                    FOR d in @vertices
                     UPDATE {_key: d._key} WITH  {_is_latest: d._id == @revision_id} IN siemrules_vertex_collection
                    RETURN TRUE
                )

                LET edge_deletions = (
                    FOR d in @edges
                    UPDATE {_key: d._key} WITH {_is_latest: d._from == @revision_id} IN siemrules_edge_collection
                    RETURN TRUE
                )
                RETURN {vertex_deletions, edge_deletions}
                
        ''', bind_vars=dict(revision_id=revert_key_id, vertices=rules, edges=rels), paginate=False)

    return True


