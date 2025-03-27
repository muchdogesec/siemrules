import json
from rest_framework import request
from django.http import HttpRequest, HttpResponse
from django.conf import settings
import typing

if typing.TYPE_CHECKING:
    from .. import settings

from siemrules.siemrules.reports import fix_report_id
from siemrules.siemrules.models import TLP_LEVEL_STIX_ID_MAPPING
from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings



RULES_SORT_FIELDS = [
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
]

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
                    FILTER doc._id == d._from AND d.relationship_type == 'mitre-attack'
                    FILTER @attack_ids[? ANY FILTER CONTAINS(d.description, CURRENT)]
                    LIMIT 1
                    RETURN TRUE
                ) > 0
            ''')
        
    if q := helper.query_as_array('cve_id'):
        binds['cve_ids'] = [r.upper() for r in q]
        filters.append('''
            FILTER LENGTH(
                FOR d IN siemrules_edge_collection
                    FILTER doc._id == d._from AND d.relationship_type == 'nvd-cve'
                    FILTER @cve_ids[? ANY FILTER CONTAINS(d.description, CURRENT)]
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
    # return HttpResponse(f"{query}\n\n//"+json.dumps(binds))
    return helper.execute_query(query, bind_vars=binds)

def get_single_rule(indicator_id):
    r = request.Request(HttpRequest())
    r.query_params.update(indicator_id=indicator_id)
    return get_rules(r)