from functools import lru_cache
import os
import time
import django
from django.conf import settings
from django.http import HttpRequest
import pytest

from dateutil.parser import parse as parse_date

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

from siemrules.siemrules.arangodb_helpers import (
    RULES_SORT_FIELDS,
    get_rules,
    get_single_rule,
    delete_rule,
    indicator_to_rule,
)
from rest_framework.exceptions import NotFound
from rest_framework.request import Request

from tests.src.utils import is_sorted


@pytest.mark.parametrize(
    "indicator_id",
    [
        "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",  # base rule
        "indicator--0e95725d-7320-415d-80f7-004da920fc11",  # correlation rule
    ],
)
@pytest.mark.parametrize(
    "payload",
    [
        {
            "tlp_level": "amber+strict",
            "title": "Cloned Sigma Rule",
            "description": "Cloned Description for Sigma Rule",
        },
        {
            "tlp_level": "amber",
            "title": "Cloned Sigma Rule 2",
        },
        {
            "title": "Cloned Sigma Rule 3",
            "identity": {
                "id": "identity--b1ae1a15-abcd-abcd-abcd-1b9678f35e15",
                "name": "Test Identity",
                "spec_version": "2.1",
                "type": "identity",
            },
        },
        {"description": "Cloned Description for Sigma Rule 4"},
    ],
)
def test_clone(subtests, client: django.test.Client, indicator_id, payload):
    rule_url = f"/api/v1/rules/{indicator_id}/"
    orig_rule_resp = client.get(rule_url)
    assert orig_rule_resp.status_code == 200
    orig_indicator = orig_rule_resp.json()
    clone_resp = client.post(rule_url + "clone/", data=payload)
    assert clone_resp.status_code == 200
    cloned_indicator = clone_resp.json()
    cloned_detection = rule_to_detection(cloned_indicator)
    orig_detection = rule_to_detection(orig_indicator)
    with subtests.test("description"):
        if description := payload.get("description"):
            assert (
                cloned_indicator["description"] == description
            ), "indicator.description was not updated"
            assert (
                cloned_detection.description == description
            ), "rule.description not updated"
        else:
            assert (
                cloned_detection.description == orig_detection.description
            ), "rule.description should be the same"
            assert cloned_indicator.get("description") == orig_indicator.get(
                "description"
            ), "indicator.description should be the same"

    with subtests.test("title/name"):
        if title := payload.get("title"):
            assert cloned_indicator["name"] == title, "indicator.name was not updated"
            assert cloned_detection.title == title, "rule.title was not updated"
        else:
            assert (
                cloned_detection.title == orig_detection.title
            ), "rule.title should be the same"
            assert cloned_indicator.get("name") == orig_indicator.get(
                "name"
            ), "indicator.name should be the same"

    with subtests.test("tlp_level"):
        if "tlp_level" in payload:
            assert (
                TLP_LEVEL_STIX_ID_MAPPING.get(TLP_Levels(payload["tlp_level"]))
                in cloned_indicator["object_marking_refs"]
            )
            tlp_tag = "tlp." + payload["tlp_level"].replace("+", "-")
            assert tlp_tag in cloned_detection.tags
            assert set(
                [t for t in orig_detection.tags if not t.startswith("tlp.")]
            ) == (set(cloned_detection.tags).difference([tlp_tag]))
        else:
            assert (
                cloned_indicator["object_marking_refs"][0]
                in orig_indicator["object_marking_refs"]
            )
            assert set(orig_detection.tags) == set(cloned_detection.tags)

    with subtests.test("identity"):
        identity = payload.get("identity", settings.STIX_IDENTITY)
        assert identity["id"] == cloned_indicator["created_by_ref"]
        assert cloned_detection.author == identity["id"]

    assert cloned_detection.date == orig_detection.date, "rule.date should be the same"
    assert (
        not cloned_detection.modified
        or cloned_detection.modified == parse_date(cloned_indicator["modified"]).date()
    ), "rule.modified must match indicator.modified"
    assert (
        cloned_indicator["created"] == orig_indicator["created"]
    ), "indicator.created must be the same"
    assert cloned_indicator["id"] != orig_indicator["id"], "stix id should change"


def rule_to_detection(indicator):
    cloned_detection = indicator_to_rule(indicator)
    if isinstance(cloned_detection, tuple):
        cloned_detection = cloned_detection[0]
    return cloned_detection
