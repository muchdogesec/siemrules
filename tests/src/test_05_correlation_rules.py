import uuid
import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from siemrules.siemrules import models
from siemrules.siemrules.views import CorrelationRuleView
from rest_framework.validators import ValidationError
from siemrules.siemrules import correlations




correlation_url = "/api/v1/correlation-rules/"


def test_correlation_create__manual(client: django.test.Client):
    rule = """
title: Many failed logins
id: 0e95725d-7320-415d-80f7-004da920fc11
description: "my description"
correlation:
    type: event_count
    rules:
        - 9e2536b0-988b-598d-8cc3-407f9f13fc61
    group-by:
        - ComputerName
    timespan: 1h
    condition:
        gte: 100
tags:
    - tlp.amber
"""
    with patch("siemrules.worker.tasks.new_correlation_task") as mock_task:
        response = client.post(
            correlation_url + "create/yml/", format="sigma", data=rule, content_type='application/sigma+yaml'
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        mock_task.assert_called_once()
        job: models.Job = mock_task.mock_calls[0].args[0]
        assert job.type == models.JobType.CORRELATION_SIGMA
        assert job.data["input_form"] == "sigma"
        assert "correlation_id" in job.data


def rule_model():
    return correlations.models.RuleModel(
        title="Test title",
        description="Test description",
        author='{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-abcd-431e-b990-1b9678f35e15","name":"Test Identity"}',
        tags=["tlp.green"],
        correlation=correlations.models.Correlation(
            type="event_count",
            rules=["9e2536b0-988b-598d-8cc3-407f9f13fc61"],
            timespan="1m",
            condition=dict(lte=12),
            group_by=["some-name"],
        ),
    )


@pytest.mark.parametrize(
    ["author", "job_data", "expected_identity"],
    [
        pytest.param(
            '{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-abcd-431e-b990-1b9678f35e15","name":"Test Identity"}',
            None,
            "identity--b1ae1a15-abcd-431e-b990-1b9678f35e15",
            id="rule.author set",
        ),
        pytest.param(
            None,
            None,
            "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
            id="use default identity",
        ),
        pytest.param(
            None,
            {
                "identity": {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": "identity--a1ae1a15-abcd-ef12-b990-1b9678f35e15",
                    "name": "Test Identity 2",
                }
            },
            "identity--a1ae1a15-abcd-ef12-b990-1b9678f35e15",
            id="identity object passed",
        ),
    ],
)
def test_add_rule_indicator_identity_in_objects(author, job_data, expected_identity):
    rule = rule_model()
    rule.author = author

    objects = correlations.correlations.add_rule_indicator(rule, job_data=job_data)
    assert expected_identity in [
        obj["id"] for obj in objects
    ], "objects must include identity object"
    assert (
        expected_identity
        == [obj["created_by_ref"] for obj in objects if obj["type"] == "indicator"][0]
    ), "created_by_ref must be passed author.id"
    assert rule.author == expected_identity, "author must be replaced with identity.id"


def test_add_rule_indicator_relationships_in_objects():
    rule = rule_model()

    related_indicators = [
        dict(
            id="indicator--" + str(uuid.uuid4()),
            _id="some_id",
            type="indicator",
            pattern="{}",
            name=f"indicator #{i}",
        )
        for i in range(5)
    ]
    objects = correlations.correlations.add_rule_indicator(
        rule, base_rule_indicators=related_indicators
    )
    correlation_indicator = objects[0]
    relations_taget_refs = {
        obj["target_ref"]: obj
        for obj in objects
        if obj["type"] == "relationship" and obj["relationship_type"] == "contains-rule"
    }
    assert len(relations_taget_refs) == len(
        related_indicators
    ), "related indicators and relationship of type 'contains-rule' must have same length"
    for related_indicator in related_indicators:
        assert related_indicator["id"] in relations_taget_refs, "missing relationship"
        rel_obj = relations_taget_refs[related_indicator["id"]]
        assert (
            rel_obj["_to"] == related_indicator["_id"]
        ), "rel._to must be set to indicator._id for edge connection on arangodb"
        assert rel_obj["created_by_ref"] == rule.author
        assert rel_obj["created"] == correlation_indicator["created"]
        assert rel_obj["modified"] == correlation_indicator["modified"]
        assert (
            rel_obj["object_marking_refs"]
            == correlation_indicator["object_marking_refs"]
        )
        assert (
            rule.title in rel_obj["description"]
        ), "correlation indicator name must be in description"
        assert (
            related_indicator["name"] in rel_obj["description"]
        ), "bundled indicator name must be in description"


@pytest.mark.parametrize(
    ["rule", "job_data", "expected_dict"],
    [
        (
            None,
            None,
            dict(
                created_by_ref="identity--b1ae1a15-abcd-431e-b990-1b9678f35e15",
                description="Test description",
            ),
        ),
        (
            dict(references=["https://someurl.net/path1", "https://someurl.net/path2"]),
            dict(correlation_id="97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"),
            dict(id="indicator--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"),
        ),
        (
            dict(tags=["tlp.amber-strict"]),
            None,
            dict(
                object_marking_refs=[
                    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
                    "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb",
                ]
            ),
        ),
    ],
)
def test_add_rule_indicator_correlation_indicator(rule, job_data, expected_dict):
    rule = rule_model().model_copy(update=rule or {})
    related_indicators = []

    with patch(
        "siemrules.siemrules.correlations.correlations.make_rule",
        return_value="sigma pattern",
    ) as mock_make_rule, patch(
        "siemrules.siemrules.correlations.correlations.rules_from_indicators",
        return_value=[],
    ) as mock_rules_from_indicators:
        objects = correlations.correlations.add_rule_indicator(
            rule, job_data=job_data, base_rule_indicators=related_indicators
        )

        mock_rules_from_indicators.assert_called_once_with(related_indicators)
        mock_make_rule.assert_called_once_with(
            rule, mock_rules_from_indicators.return_value, rule.rule_id
        )
        correlation_indicator = objects[0]
        for k in expected_dict:
            assert correlation_indicator[k] == expected_dict[k]
        assert correlation_indicator["name"] == rule.title
        assert correlation_indicator["description"] == rule.description
        assert (
            rule.tlp_level.value["id"] in correlation_indicator["object_marking_refs"]
        ), "tlp_level marker not in object_marking_refs"
        assert rule.tlp_level.value["id"] in [
            obj["id"] for obj in objects
        ], "tlp_level marking-definition object must be part of the bundle"

        assert correlation_indicator["created"] == correlation_indicator["valid_from"]
        assert correlation_indicator["pattern_type"] == "sigma"
        assert correlation_indicator["pattern"] == mock_make_rule.return_value
        for ref_url in rule.references or []:
            assert ref_url in [
                r["url"]
                for r in correlation_indicator["external_references"]
                if r["source_name"] == "siemrules"
            ]


@pytest.mark.parametrize(
    "rule_payload",
    [
        {
            "rules": ["8af82832-2abd-5765-903c-01d414dae1e9"],
            "prompt": "create a tempral correlation",
            "ai_provider": "openai",
            "created": "2025-03-02T14:36:52.663Z",
            "identity": {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--b1ae1a15-abcd-431e-b990-1b9678f35e15",
                "name": "Test Identity",
            },
            "modified": "2025-04-17T14:36:52.663Z",
        }
    ],
)
def test_correlation_create__prompt(client: django.test.Client, rule_payload: dict):

    with patch("siemrules.worker.tasks.new_correlation_task") as mock_task:
        response = client.post(
            correlation_url + "create/prompt/",
            data=rule_payload,
            content_type="application/json",
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        mock_task.assert_called_once()
        job: models.Job = mock_task.mock_calls[0].args[0]
        assert job.type == models.JobType.CORRELATION_PROMPT
        assert job.data["input_form"] == "ai_prompt"
        assert job.data["ai_provider"] == rule_payload["ai_provider"]
        assert job.data["prompt"] == rule_payload["prompt"]
        assert "correlation_id" in job.data
        assert rule_payload.get("tlp_level", "clear") == job.data["tlp_level"]

def test_modify_correlation_from_prompt(client: django.test.Client):
    pass


@pytest.mark.parametrize(
    ["rule_ids", "should_fail"],
    [
        [["9e2536b0-988b-598d-8cc3-407f9f13fc61"], False],
        [["abcd36b0-efab-598d-8cc3-407f9f13fc61"], True],
        [
            [
                "abcd36b0-efab-598d-8cc3-407f9f13fc61",
                "9e2536b0-988b-598d-8cc3-407f9f13fc61",
            ],
            True,
        ],
    ],
)
def test_get_rules(rule_ids, should_fail):
    if should_fail:
        with pytest.raises(ValidationError):
            CorrelationRuleView.get_rules(rule_ids)
    else:
        rules = CorrelationRuleView.get_rules(rule_ids)
        assert set([r["id"][11:] for r in rules]) == set(rule_ids)
