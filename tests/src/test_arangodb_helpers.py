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
from siemrules.worker import tasks
from tests.src import data as test_data
from rest_framework.response import Response
from rest_framework.validators import ValidationError

from siemrules.siemrules.arangodb_helpers import RULES_SORT_FIELDS, get_rules, get_single_rule
from rest_framework.request import Request

from tests.src.utils import is_sorted


from .test_reports import upload_bundles


@pytest.mark.parametrize(
    ["params", "expected_ids"],
    [
        pytest.param(dict(attack_id="T105911"), [], id="attack_id bad"),
        pytest.param(
            dict(attack_id="T1059"),
            ["indicator--7ff1540b-5f76-57ea-84ef-533ad474e854"],
            id="attack_id x1",
        ),
        pytest.param(
            dict(attack_id="T1059,TA0001"),
            [
                "indicator--7ff1540b-5f76-57ea-84ef-533ad474e854",
                "indicator--6d97794b-c2d8-5e32-9ec0-1b952ff91c8b",
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
                "indicator--6d97794b-c2d8-5e32-9ec0-1b952ff91c8b",
                "indicator--7ff1540b-5f76-57ea-84ef-533ad474e854",
                "indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7",
            ],
            id="good identity",
        ),
        pytest.param(
            dict(created_by_ref="identity--a4d70b75-6f4a-5d19-9137-da863edd33d7", attack_id="T1059"),
            [
                "indicator--7ff1540b-5f76-57ea-84ef-533ad474e854",
            ],
            id="good identity + attacK_id",
        ),
        pytest.param(dict(cve_id='CVE-2022-99999'), [], id='cve_id bad'),
        pytest.param(dict(cve_id='CVE-2024-1234,CVE-2024-123456'), ["indicator--7ff1540b-5f76-57ea-84ef-533ad474e854"], id='cve_id good+bad'),
        pytest.param(dict(cve_id='CVE-2024-3094,CVE-2024-1234'), ["indicator--7ff1540b-5f76-57ea-84ef-533ad474e854", "indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7"], id='cve_id good+good'),
        pytest.param(dict(cve_id='CVE-2024-3094,CVE-2024-1234', attack_id="T1059"), ["indicator--7ff1540b-5f76-57ea-84ef-533ad474e854"], id='cve_id + attack_id'),
        pytest.param(dict(file_id='some-id'), [], id='bad file id'),
        pytest.param(dict(file_id='60915f4c-fa2d-5bf1-b7d1-d7ecab167560'), ["indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7"], id='good file id'),
        pytest.param(dict(report_id='some-id'), [], id='bad report id'),
        pytest.param(dict(report_id='report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560'), ["indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7"], id='good report id'),
        pytest.param(dict(name='this will not be found'), [], id='bad name'),
        pytest.param(dict(name='tarballs'), ["indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7"], id='good name'),
        pytest.param(dict(name='taRbALls'), ["indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7"], id='good name bad case'),
        pytest.param(dict(name='eLemENtor'), ["indicator--7ff1540b-5f76-57ea-84ef-533ad474e854"], id='good name bad case 2'),
        pytest.param(dict(tlp_level='green'), [
            'indicator--6d97794b-c2d8-5e32-9ec0-1b952ff91c8b',
            'indicator--b18fc815-94c5-5dab-813b-2ad96c102fd7'
        ], id='tlp level green'),
        pytest.param(dict(tlp_level='amber'), ['indicator--7ff1540b-5f76-57ea-84ef-533ad474e854'], id='tlp level amber'),
        pytest.param(dict(tlp_level='clear'), [], id='tlp level amber'),
    ],
)
def test_get_rules(params, expected_ids):
    upload_bundles()
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
    upload_bundles()
    request = Request(HttpRequest())
    request.query_params.update(sort=sort_param)
    result = get_rules(request)

    param, _, direction = sort_param.rpartition('_')
    assert is_sorted(result.data['rules'], key=lambda obj: obj[param], reverse=direction=='descending')



def test_get_single_rule():
    indicator_id = "indicator--a4d70b75-6f4a-5d19-9137-da863edd33d7"
    with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_get_rules:
        get_single_rule(indicator_id)
        mock_get_rules.assert_called_once()
        request = mock_get_rules.mock_calls[0].args[0]
        assert isinstance(request, Request)
        assert request.query_params.get("indicator_id") == indicator_id
