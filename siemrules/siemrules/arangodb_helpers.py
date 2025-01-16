from rest_framework import request
from django.http import HttpRequest
from django.conf import settings
import typing
from django.db.models import TextChoices

if typing.TYPE_CHECKING:
    from .. import settings


import typing
from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings


def fix_report_id(report_id: str):
    if report_id.startswith('report--'):
        return report_id
    return "report--"+report_id

def remove_report(report_id: str):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    report_id = fix_report_id(report_id)
    bind_vars = {
            "@collection": helper.collection,
            'report_id': report_id,
    }
    query = """
        FOR doc in @@collection
        FILTER doc._stixify_report_id == @report_id
        RETURN doc._id
    """
    collections: dict[str, list] = {}
    out = helper.execute_query(query, bind_vars=bind_vars, paginate=False)
    for key in out:
        collection, key = key.split('/', 2)
        collections[collection] = collections.get(collection, [])
        collections[collection].append(key)

    deletion_query = """
        FOR _key in @objects
        REMOVE {_key} IN @@collection
        RETURN _key
    """

    for collection, objects in collections.items():
        bind_vars = {
            "@collection": collection,
            "objects": objects,
        }
        helper.execute_query(deletion_query, bind_vars, paginate=False)

RULES_SORT_FIELDS = [
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
]
class TLP_Levels(TextChoices):
    RED = "red"
    AMBER_STRICT = "amber+strict"
    AMBER = "amber"
    GREEN = "green"
    CLEAR = "clear"
TLP_LEVEL_STIX_ID_MAPPING = {
    TLP_Levels.RED: "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    TLP_Levels.CLEAR: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    TLP_Levels.GREEN: "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    TLP_Levels.AMBER: "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    TLP_Levels.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
}
def get_rules(request):
    helper = ArangoDBHelper(settings.VIEW_NAME, request, result_key="rules")
    binds = {}
    filters = []

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
            FILTER LENGTH(
                FOR d IN siemrules_edge_collection
                    FILTER doc._id == d._from AND d.relationship_type == 'mitre-attack' AND NOT doc._is_ref AND d.external_references
                    FILTER @attack_ids[? ANY FILTER CURRENT IN d.description]
                    LIMIT 1
                    RETURN TRUE
                ) > 0
            ''')

    query = """

FOR doc IN siemrules_vertex_collection
FILTER doc.type == 'indicator' AND doc._is_latest

@filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
""".replace(
        "@filters", "\n".join(filters)
    ).replace(
        "@sort_stmt",
        helper.get_sort_stmt(
            RULES_SORT_FIELDS,
        ),
    )
    # return Response([query, binds])
    return helper.execute_query(query, bind_vars=binds)

def get_single_rule(indicator_id):
    r = request.Request(HttpRequest())
    r.query_params.update(indicator_id=indicator_id)
    return get_rules(r)