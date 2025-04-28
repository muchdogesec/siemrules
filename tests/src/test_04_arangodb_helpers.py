from functools import lru_cache
import os
import time
import django
from django.http import HttpRequest
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models, reports
from siemrules.siemrules.utils import TLP_LEVEL_STIX_ID_MAPPING, TLP_Levels
from siemrules.worker import tasks
from tests.src import data as test_data
from rest_framework.response import Response
from rest_framework.validators import ValidationError

from siemrules.siemrules.arangodb_helpers import RULES_SORT_FIELDS, get_rules, get_single_rule, delete_rule
from rest_framework.exceptions import NotFound
from rest_framework.request import Request

from tests.src.utils import is_sorted


RULE_TYPES = [
    "base",
    "correlation",
]




@pytest.mark.parametrize(
    ["params", "expected_ids"],
    [
        pytest.param(dict(attack_id="T105911"), [], id="attack_id bad"),
        pytest.param(
            dict(attack_id="T1059"),
            [],
            id="attack_id bad 2",
        ),
        pytest.param(
            dict(attack_id="T1059,TA0001"),
            [
                "indicator--8af82832-2abd-5765-903c-01d414dae1e9",
            ],
            id="attack_id x2",
        ),
        pytest.param(
            dict(created_by_ref="identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15"),
            [],
            id="bad identity",
        ),
        pytest.param(
            dict(created_by_ref="identity--a4d70b75-6f4a-5d19-9137-da863edd33d7"),
            [
                "indicator--8af82832-2abd-5765-903c-01d414dae1e9",
                "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",
            ],
            id="good identity",
        ),
        pytest.param(
            dict(created_by_ref="identity--a4d70b75-6f4a-5d19-9137-da863edd33d7", attack_id="TA0001"),
            [
                "indicator--8af82832-2abd-5765-903c-01d414dae1e9",
            ],
            id="good identity + attacK_id",
        ),
        pytest.param(dict(cve_id='CVE-2022-99999'), [], id='cve_id bad'),
        pytest.param(dict(cve_id='CVE-2024-1234,CVE-2024-123456'), ["indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"], id='cve_id good+bad'),
        pytest.param(dict(cve_id='CVE-2024-3094,CVE-2024-1234'), ["indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72", "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='cve_id good+good'),
        pytest.param(dict(cve_id='CVE-2024-3094,CVE-2024-1234', attack_id="TA0005"), ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='cve_id + attack_id'),
        pytest.param(dict(file_id='some-id'), [], id='bad file id'),
        pytest.param(dict(file_id='60915f4c-fa2d-5bf1-b7d1-d7ecab167560'), ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='good file id'),
        pytest.param(dict(report_id='some-id'), [], id='bad report id'),
        pytest.param(dict(report_id='report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560'), ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='good report id'),
        pytest.param(dict(name='this will not be found'), [], id='bad name'),
        pytest.param(dict(name='tarballs'), ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='good name'),
        pytest.param(dict(name='taRbALls'), ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"], id='good name bad case'),
        pytest.param(dict(name='eLemENtor'), ["indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"], id='good name bad case 2'),
        pytest.param(dict(tlp_level='green'), [
            'indicator--8af82832-2abd-5765-903c-01d414dae1e9',
            'indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61'
        ], id='tlp level green'),
        pytest.param(dict(tlp_level='amber'), ['indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72'], id='tlp level amber 1'),
        pytest.param(dict(tlp_level='clear'), [], id='tlp level clear'),
    ],
)
def test_get_rules(params, expected_ids):
    expected_ids = set(expected_ids)
    request = Request(HttpRequest())
    request.query_params.update(params)
    result = get_rules(request)

    assert {obj["id"] for obj in result.data["rules"]} == expected_ids

@pytest.mark.parametrize(
        'sort_param',
        RULES_SORT_FIELDS
)
def test_get_rules_sort(sort_param):
    request = Request(HttpRequest())
    request.query_params.update(sort=sort_param)
    result = get_rules(request)

    param, _, direction = sort_param.rpartition('_')
    assert is_sorted(result.data['rules'], key=lambda obj: obj[param], reverse=direction=='descending')


@pytest.mark.parametrize(
        "rule_type",
        RULE_TYPES
)
def test_get_single_rule(rule_type):
    indicator_id = "indicator--a4d70b75-6f4a-5d19-9137-da863edd33d7"
    with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_get_rules:
        get_single_rule(indicator_id, rule_type=rule_type)
        mock_get_rules.assert_called_once()
        request = mock_get_rules.mock_calls[0].args[0]
        mock_get_rules.assert_called_once_with(request, paginate=False, rule_type=rule_type)
        assert isinstance(request, Request)
        assert request.query_params.get("indicator_id") == indicator_id

def test_get_single_rule_404():
    indicator_id = "indicator--a4d70b75-6f4a-5d19-9137-da863edd33d7"
    with pytest.raises(NotFound), patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_get_rules:
        mock_get_rules.return_value = []
        get_single_rule(indicator_id)
        mock_get_rules.assert_called_once()


def test_delete_rules():
    rule_id = "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"
    report_id = 'report--cc297329-2c8d-55f3-bef9-3137bb9d87a7'
    assert delete_rule(rule_id) == True
    from rest_framework import request
    from dogesec_commons.objects.helpers import ArangoDBHelper
    from siemrules import settings
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    for obj in helper.db.collection('siemrules_vertex_collection').all():
        assert obj['id'] != rule_id, "rule not deleted"
        if obj['id'] == report_id:
            assert rule_id not in obj['object_refs'], "rule not removed from report.object_refs"
    for obj in helper.db.collection('siemrules_edge_collection').all():
        assert obj['source_ref'] != rule_id, "relationships to rule not deleted"


tlp_levels_visible_to_all = {TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.CLEAR], TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.GREEN]}

@pytest.mark.parametrize(
        "path",
        [
            "reports",
            "correlation-rules",
            "rules",
        ]
)
def test_visible_to(client: django.test.Client, subtests, path):
    key = 'rules' if path != 'reports' else 'objects'
    path_url = f"api/v1/{path}/objects/"
    resp = client.get(path_url)
    assert resp.status_code == 200
    objects = resp.data[key]
    created_by_refs = {obj['created_by_ref'] for obj in objects}
    created_by_refs.add("identity--abcdef12-abcd-431e-abcd-1b9678abcdef") # bad identity id should return all green and clears
    for identity_id in created_by_refs:
        with subtests.test("test visible_to", identity_id=identity_id, path=path):
            resp = client.get(path_url, query_params=dict(visible_to=identity_id))
            objects = resp.data[key]
            for obj in objects:
                assert obj['created_by_ref'] == identity_id or not tlp_levels_visible_to_all.isdisjoint(obj['object_marking_refs'])