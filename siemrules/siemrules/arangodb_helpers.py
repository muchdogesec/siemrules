import contextlib
from datetime import UTC, datetime
import json
import uuid
from rest_framework import request
from django.http import HttpRequest
from django.conf import settings
import typing
from stix2.serialization import serialize as stix2_serialize
from dogesec_commons.objects.helpers import OBJECT_TYPES

from siemrules.siemrules.correlations import correlations
from siemrules.siemrules.correlations.correlations import yaml_to_rule
from siemrules.siemrules.modifier import yaml_to_detection
from siemrules.siemrules.utils import TLP_LEVEL_STIX_ID_MAPPING, TLP_Levels

from txt2detection.models import TLP_LEVEL as T2D_TLP_LEVEL, SigmaRuleDetection
from siemrules.siemrules.correlations.models import RuleModel, set_tlp_level_in_tags

from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings
from rest_framework.exceptions import NotFound, ParseError, ValidationError
from rest_framework.response import Response
from stix2.utils import format_datetime


RULES_SORT_FIELDS = [
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
]


def fix_report_id(report_id: str):
    if report_id.startswith("report--"):
        return report_id
    return "report--" + report_id


def get_rules(request: request.Request, paginate=True, all_versions=False, nokeep=True):
    helper = ArangoDBHelper(settings.VIEW_NAME, request, result_key="rules")
    binds = {}
    filters = []

    version_filter = "doc._is_latest"
    if version := helper.query.get("version"):
        binds["version"] = version
        version_filter = "doc.modified == @version"
    if all_versions:
        version_filter = "TRUE"

    visible_to_filter = ""
    if q := helper.query.get("visible_to"):
        binds["visible_to"] = q
        binds["marking_visible_to_all"] = (
            TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.GREEN],
            TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.CLEAR],
        )
        visible_to_filter = "FILTER doc.created_by_ref == @visible_to OR @marking_visible_to_all ANY IN doc.object_marking_refs"

    report_ids = helper.query_as_array("report_id")
    if file_ids := helper.query_as_array("file_id"):
        report_ids.extend(map(lambda id: fix_report_id(id), file_ids))

    if report_ids:
        binds["report_ids"] = report_ids
        filters.append("FILTER doc._stixify_report_id IN @report_ids")

    indicator_ids = helper.query_as_array("indicator_id")
    if base_rules := helper.query_as_array("base_rule"):
        matched_ids = helper.execute_query(
            "FOR doc IN siemrules_edge_collection FILTER doc.target_ref IN @base_rules AND doc.relationship_type == 'contains-rule' RETURN doc.source_ref",
            paginate=False,
            bind_vars=dict(base_rules=base_rules),
        )
        indicator_ids = list(
            set(matched_ids).intersection(indicator_ids or matched_ids)
        )

    if correlation_rules := helper.query_as_array("correlation_rule"):
        matched_ids = helper.execute_query(
            "FOR doc IN siemrules_edge_collection FILTER doc.source_ref IN @correlation_rules AND doc.relationship_type == 'contains-rule' RETURN doc.target_ref",
            paginate=False,
            bind_vars=dict(correlation_rules=correlation_rules),
        )
        indicator_ids = list(
            set(matched_ids).intersection(indicator_ids or matched_ids)
        )

    if indicator_ids or base_rules or correlation_rules:
        binds["indicator_ids"] = indicator_ids
        filters.append("FILTER doc.id in @indicator_ids")

    if name := helper.query.get("name", "").lower():
        binds["name"] = name
        filters.append("FILTER CONTAINS(LOWER(doc.name), @name)")

    if tlp_level := helper.query.get("tlp_level"):
        binds["tlp_level_stix_id"] = TLP_LEVEL_STIX_ID_MAPPING.get(tlp_level)
        filters.append("FILTER @tlp_level_stix_id IN doc.object_marking_refs")

    if values := helper.query_as_array("created_by_ref"):
        binds["created_by_ref"] = values
        filters.append("FILTER doc.created_by_ref IN @created_by_ref")

    if q := helper.query_as_array("attack_id"):
        binds["attack_ids"] = [r.upper() for r in q]
        filters.append(
            """
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name == 'mitre-attack' AND CURRENT.external_id IN @attack_ids]
            """
        )

    if q := helper.query_as_array("cve_id"):
        binds["cve_ids"] = [r.upper() for r in q]
        filters.append(
            """
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name == 'cve' AND CURRENT.external_id IN @cve_ids]
            """
        )

    if rule_type := helper.query.get("rule_type"):
        rule_type, _, _ = rule_type.partition("-")
        filters.append("FILTER doc.x_sigma_type == @rule_type")
        binds.update(rule_type=rule_type)

    query = (
        """

FOR doc IN siemrules_vertex_collection
FILTER doc.type == 'indicator' AND #version

@filters
#visible_to
@sort_stmt
#LIMIT
RETURN KEEP(doc, KEYS(doc, #NOKEEP))
""".replace(
            "#version", version_filter
        )
        .replace("@filters", "\n".join(filters))
        .replace("#NOKEEP", str(nokeep))
        .replace(
            "@sort_stmt",
            helper.get_sort_stmt(
                RULES_SORT_FIELDS,
            ),
        )
        .replace("#visible_to", visible_to_filter)
    )
    limit_str = ""
    if paginate:
        limit_str = "LIMIT @offset, @count"
    query = query.replace("#LIMIT", limit_str)
    # return HttpResponse(f"{query}\n\n//"+json.dumps(binds))
    return helper.execute_query(query, bind_vars=binds, paginate=paginate)


def request_from_queries(**queries):
    r = request.Request(HttpRequest())
    r.query_params.update(queries)
    return r


def get_single_rule(indicator_id, version=None, nokeep=True, **kwargs):
    r = request_from_queries(indicator_id=indicator_id, version=version, **kwargs)
    rules = get_rules(r, paginate=False, nokeep=nokeep)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    return Response(rules[0])


def get_single_rule_versions(indicator_id, rule_type):
    r = request_from_queries(indicator_id=indicator_id, rule_type=rule_type)
    rules = get_rules(r, paginate=False, all_versions=True)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    return Response(sorted([rule["modified"] for rule in rules], reverse=True))


def get_objects_for_rule(
    indicator_id, request, version=None, rule_type=None, with_limit=True
):
    rule = get_single_rule(indicator_id, version=version, nokeep=False).data

    helper = ArangoDBHelper(settings.VIEW_NAME, request)
    filters = []
    binds = {"rule_key": rule["_id"], "@view": settings.VIEW_NAME}
    if types := helper.query_as_array("types"):
        filters.append("FILTER doc.type IN @types")
        binds["types"] = list(OBJECT_TYPES.intersection(helper.query_as_array("types")))

    if helper.query_as_bool("ignore_embedded_sro", default=False):
        filters.append("FILTER doc._is_ref != TRUE")

    if rule_type == "base-rule":
        obj_ids_str = "UNIQUE(FLATTEN([@rule_key, rel_ids], 3))"
    else:
        obj_ids_str = "UNIQUE(FLATTEN([@rule_key, rel_ids, secondary_rel_ids], 3))"

    query = """
    LET rel_ids = FLATTEN(FOR rel IN siemrules_edge_collection FILTER rel._from == @rule_key OR rel._to == @rule_key RETURN [rel._from, rel._to, rel._id])
    LET rel_ids_filtered = (FOR f IN rel_ids FILTER CONTAINS(f, 'indicator--') RETURN f)
    LET secondary_rel_ids = (FOR rel IN siemrules_edge_collection FILTER rel._from IN rel_ids_filtered RETURN [rel._from, rel._to, rel._id])
    LET obj_ids = #obj_ids_str
    FOR doc IN @@view
    SEARCH doc._id IN obj_ids
    #filters
    //LIMIT
    RETURN KEEP(doc, KEYS(doc, TRUE))
    """
    query = query.replace("#filters", "\n".join(filters)).replace(
        "#obj_ids_str", obj_ids_str
    )
    if with_limit:
        query = query.replace("//LIMIT", "LIMIT @offset, @count")
    else:
        return helper.execute_query(query, bind_vars=binds, paginate=False)
    return helper.execute_query(query, bind_vars=binds)


def get_objects_by_id(indicator_id):
    helper = ArangoDBHelper(settings.VIEW_NAME, request_from_queries())
    objects = helper.execute_query(
        """
            FOR doc IN siemrules_vertex_collection
            FILTER doc.type IN ['report', 'indicator']
            FILTER doc.id == @stix_id OR (doc.type == 'report' AND @stix_id IN doc.object_refs)
            FILTER doc._is_latest == TRUE
            RETURN doc
    """,
        bind_vars=dict(stix_id=indicator_id),
        paginate=False,
    )
    report = obj = None
    with contextlib.suppress(IndexError):
        obj = [obj for obj in objects if obj["id"] == indicator_id][0]
        report = [obj for obj in objects if obj["type"] == "report"][0]
    if not obj:
        raise NotFound(f"no rule with id `{indicator_id}`")

    rels = helper.execute_query(
        """
            FOR doc IN siemrules_edge_collection
            FILTER doc._from == @stix_id_key
            RETURN doc
    """,
        bind_vars=dict(stix_id_key=obj["_id"]),
        paginate=False,
    )

    all_objs = [obj] + rels
    return report, obj, all_objs


from stix2arango.stix2arango import Stix2Arango


def make_upload(report_id, bundle, s2a_kwargs=None):
    s2a_kwargs = s2a_kwargs or {}
    file_id = report_id.removeprefix("report--")
    s2a = Stix2Arango(
        file=None,
        database=settings.ARANGODB_DATABASE,
        collection=settings.ARANGODB_COLLECTION,
        stix2arango_note=f"siemrules-file--{file_id}" if file_id else "",
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        ignore_embedded_relationships=False,
        **s2a_kwargs,
    )
    if report_id:
        s2a.arangodb_extra_data = dict(_stixify_report_id=report_id)
    s2a.run(data=bundle)


def modify_rule(indicator_id, old_modified, new_modified, new_objects):
    report, obj, all_objs = get_objects_by_id(indicator_id)

    if obj["modified"] != old_modified:
        raise Exception("object modified on db after modification job started")
    helper = ArangoDBHelper(settings.VIEW_NAME, request_from_queries())
    helper.execute_query(
        """
            LET vertex_deletions = (
                        FOR doc IN siemrules_vertex_collection
                        FILTER doc._key IN @keys
                        UPDATE doc WITH {_is_latest: FALSE} IN siemrules_vertex_collection
                        RETURN doc.id
            )

            LET edge_deletions = (
                        FOR doc IN siemrules_edge_collection
                        FILTER doc._key IN @keys
                        UPDATE doc WITH {_is_latest: FALSE} IN siemrules_edge_collection
                        RETURN doc.id
            )
            RETURN {vertex_deletions, edge_deletions}
            
    """,
        bind_vars=dict(keys=[obj["_key"] for obj in all_objs]),
        paginate=False,
    )

    make_upload(obj.get("_stixify_report_id", ""), make_bundle(new_objects))

    if report:
        object_refs: list = report["object_refs"] + [obj["id"] for obj in new_objects]
        for ref in all_objs:
            try:
                object_refs.remove(ref["id"])
            except Exception as e:
                print(e)
                pass
        helper.execute_query(
            "UPDATE {_key: @report_key} WITH @report_update IN siemrules_vertex_collection",
            bind_vars=dict(
                report_key=report["_key"],
                report_update=dict(object_refs=object_refs, modified=new_modified),
            ),
            paginate=False,
        )


def delete_rule(indicator_id):
    helper = ArangoDBHelper(settings.VIEW_NAME, request_from_queries())
    new_modified = format_datetime(datetime.now(UTC))
    objects = helper.execute_query(
        """
            FOR doc IN siemrules_vertex_collection
            FILTER doc.type IN ['report', 'indicator']
            FILTER doc.id == @stix_id OR (doc.type == 'report' AND @stix_id IN doc.object_refs)
            RETURN KEEP(doc, "id", "_id", "_key", "object_refs", "type", "modified")
    """,
        bind_vars=dict(stix_id=indicator_id),
        paginate=False,
    )

    report = None
    rules = []
    with contextlib.suppress(IndexError):
        for obj in objects:
            if obj["type"] == "report":
                report = obj
                continue
            if obj["id"] == indicator_id:
                rules.append(obj)

    if not rules:
        raise NotFound(f"no rules with id `{indicator_id}`")

    rels = helper.execute_query(
        """
            FOR doc IN siemrules_edge_collection
            FILTER doc._from IN @stix_id_keys
            RETURN KEEP(doc, "id", "_id", "_from", "_to", "_key", "modified", "relationship_type")
    """,
        bind_vars=dict(stix_id_keys=[obj["_id"] for obj in rules]),
        paginate=False,
    )

    # check that there is no correlation using the rule
    correlation_rels = related_correlation_rules([indicator_id])
    if correlation_rels:
        raise ValidationError(
            dict(
                message=f"sorry, you cannot delete this rule because it is linked to {len(correlation_rels)} correlation(s)",
                correlations=correlation_rels,
            )
        )

    # perform deletion
    helper.execute_query(
        """
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
            
    """,
        bind_vars=dict(keys=[obj["_key"] for obj in rules + rels]),
        paginate=False,
    )

    # remove rule from report
    if report:
        report["object_refs"].remove(indicator_id)
        for obj in rules:
            with contextlib.suppress(Exception):
                report["object_refs"].remove(obj["id"])

        helper.execute_query(
            "UPDATE {_key: @report_key} WITH @report_update IN siemrules_vertex_collection",
            bind_vars=dict(
                report_key=report["_key"],
                report_update=dict(
                    object_refs=report["object_refs"], modified=new_modified
                ),
            ),
            paginate=False,
        )

    return True


def indicator_to_rule(
    indicator: dict,
) -> tuple[RuleModel | SigmaRuleDetection, list[dict]]:
    match indicator['x_sigma_type']:
        case 'base':
            return yaml_to_detection(indicator["pattern"]), []
        case 'correlation':
            return yaml_to_rule(indicator["pattern"])
        case _:
            raise ParseError("unable to determine rule type")


def make_clone(indicator_id: str, new_uuid: str, data: dict):
    _, _, new_uuid = new_uuid.rpartition("--")
    r = request_from_queries(indicator_id=indicator_id)
    helper = ArangoDBHelper(settings.VIEW_NAME, r)
    now = datetime.now(UTC)
    now_str = now.isoformat().replace("+00:00", "Z")

    rules = get_rules(r, paginate=False, nokeep=False)
    if not rules:
        raise NotFound(f"no rule with id `{indicator_id}`")
    rule = rules[0]
    old_stix_id = rule["id"]
    _, _, old_uuid = old_stix_id.rpartition("--")
    old_arango_id = rule["_id"]
    rule["id"] = "indicator--" + new_uuid
    old_pattern, other_documents = indicator_to_rule(rule)
    author_ref = old_pattern.author
    identity = data.get("identity", settings.STIX_IDENTITY.copy())
    author_ref = identity["id"]

    tlp_level = old_pattern.tlp_level
    if l := data.get("tlp_level"):
        tlp_level = T2D_TLP_LEVEL.get(l)

    new_pattern = old_pattern.model_copy()
    ### update title/description/tlp_level/modified
    new_pattern.title = rule["name"] = data.get("title", old_pattern.title)
    new_pattern.description = rule["description"] = data.get(
        "description", old_pattern.description
    )
    new_pattern.author = author_ref
    set_tlp_level_in_tags(new_pattern.tags, tlp_level.name)
    new_pattern.related = new_pattern.related or []
    new_pattern.related.append(dict(id=old_uuid, type="derived"))
    new_pattern.date = now.date()
    new_pattern.modified = now.date()

    ##############
    report = None
    if isinstance(new_pattern, RuleModel):
        rule["pattern"] = correlations.make_rule(new_pattern, other_documents, new_uuid)
    else:
        new_pattern.id = new_pattern.detection_id = new_uuid
        new_pattern.related = new_pattern.related or []
        rule["pattern"] = new_pattern.make_rule(None)
        report = helper.execute_query(
            "FOR report IN siemrules_vertex_collection FILTER report.id == @report_id RETURN report",
            bind_vars=dict(report_id=rule["_stixify_report_id"]),
            paginate=False,
        )[0]

    rels: list[dict] = helper.execute_query(
        """
            FOR d in siemrules_edge_collection
            FILTER d._from == @revision_id AND d._is_ref != TRUE
            RETURN d
        """,
        bind_vars=dict(revision_id=rule["_id"]),
        paginate=False,
    )

    objects = [rule] + rels

    new_marking_refs = [
        tlp_level.value["id"],
        "marking-definition--8ef05850-cb0d-51f7-80be-50e4376dbe63",
    ]

    objects.append(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "created_by_ref": author_ref,
            "created": now_str,
            "modified": now_str,
            "_to": old_arango_id,
            "relationship_type": "related-to",
            "description": f"{new_pattern.title} was derived from report {old_pattern.title}",
            "source_ref": f"indicator--{new_uuid}",
            "target_ref": f"indicator--{old_uuid}",
            "object_marking_refs": new_marking_refs,
        }
    )
    if report:
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "created_by_ref": author_ref,
                "created": now_str,
                "modified": now_str,
                "_to": report["_id"],
                "relationship_type": "related-to",
                "description": f"{new_pattern.title} was derived from report {report['name']}",
                "source_ref": f"indicator--{new_uuid}",
                "target_ref": report["id"],
                "object_marking_refs": new_marking_refs,
            }
        )

    for obj in objects:
        for k, v in [
            ("source_ref", rule["id"]),
            ("object_marking_refs", new_marking_refs),
            ("created_by_ref", author_ref),
            ("created", now_str),
            ("modified", now_str),
        ]:
            if k in obj:
                obj[k] = v

        if obj.get("type") == "relationship":
            obj.update(
                id="relationship--"
                + str(
                    uuid.uuid5(
                        settings.STIX_NAMESPACE,
                        f"{obj['source_ref']}+{obj['target_ref']}",
                    )
                )
            )

        for k in [
            "_record_modified",
            "_record_created",
            "_record_md5_hash",
            "_stixify_report_id",  # should not be removed when report is purged
            "_from",
            "_id",
            "_key",
        ]:
            obj.pop(k, None)
        obj["_is_latest"] = True

    ext_refs: list[dict] = [
        ref
        for ref in rule.get("external_references", [])
        if ref["source_name"] != "siemrules-cloned-from"
    ]
    ext_refs.append(dict(source_name="siemrules-cloned-from", external_id=old_uuid))
    rule["external_references"] = ext_refs
    rule["valid_from"] = now_str

    objects += [identity]

    make_upload(rule.get("_stixify_report_id", ""), make_bundle(objects))
    return rule


def make_bundle(objects):
    return json.loads(
        stix2_serialize(
            dict(type="bundle", id="bundle--" + str(uuid.uuid4()), objects=objects)
        )
    )


def related_correlation_rules(indicator_ids):
    helper = ArangoDBHelper(settings.VIEW_NAME, request_from_queries())
    correlation_rels = helper.execute_query(
        """
            FOR doc IN siemrules_edge_collection
            FILTER doc.target_ref IN @indicator_ids AND doc.relationship_type == "contains-rule"
            RETURN KEEP(doc, "source_ref", "modified", "relationship_type")
    """,
        bind_vars=dict(indicator_ids=indicator_ids),
        paginate=False,
    )
    return [dict(id=r["source_ref"], version=r["modified"]) for r in correlation_rels]
