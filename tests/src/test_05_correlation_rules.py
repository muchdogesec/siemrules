from functools import lru_cache
import json
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
from siemrules.siemrules.views import CorrelationRuleView, RuleView
from siemrules.worker import tasks
from tests.src import data as test_data
from rest_framework.response import Response
from rest_framework.validators import ValidationError

from siemrules.siemrules.arangodb_helpers import RULES_SORT_FIELDS, get_rules, get_single_rule, delete_rule
from rest_framework.exceptions import NotFound
from rest_framework.request import Request

from tests.src.utils import is_sorted


correlation_url = '/api/v1/correlation-rules/'

@pytest.mark.django_db
def test_correlation_create__manual(client: django.test.Client):
    rule = '''
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
'''
    with patch("siemrules.worker.tasks.new_correlation_task") as mock_task:
        response = client.post(
            correlation_url + "create/manual/", format="sigma", data=rule, content_type='application/sigma+yaml'
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        mock_task.assert_called_once()
        job: models.Job = mock_task.mock_calls[0].args[0]
        assert job.type == models.JobType.CORRELATION_SIGMA
        assert job.data['input_form'] == 'sigma'
        assert "correlation_id" in job.data


@pytest.mark.django_db
def test_correlation_create__prompt(client: django.test.Client):
    rule_payload = {
        "rules": [
            "8af82832-2abd-5765-903c-01d414dae1e9"
        ],
        "prompt": "create a tempral correlation",
        "ai_provider": "openai",
        "created": "2025-03-02T14:36:52.663Z",
        "identity":  {"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-abcd-431e-b990-1b9678f35e15","name":"Test Identity"},
        "modified": "2025-04-17T14:36:52.663Z"
    }
    with patch("siemrules.worker.tasks.new_correlation_task") as mock_task:
        response = client.post(
            correlation_url + "create/prompt/", data=rule_payload, content_type='application/json',
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        mock_task.assert_called_once()
        job: models.Job = mock_task.mock_calls[0].args[0]
        assert job.type == models.JobType.CORRELATION_PROMPT
        assert job.data['input_form'] == 'ai_prompt'
        assert job.data["ai_provider"] == rule_payload['ai_provider']
        assert job.data["prompt"] == rule_payload['prompt']
        assert "correlation_id" in job.data

@pytest.mark.parametrize(
        ["rule_ids", "should_fail"],
        [
            [["9e2536b0-988b-598d-8cc3-407f9f13fc61"], False],
            [["abcd36b0-efab-598d-8cc3-407f9f13fc61"], True],
            [["abcd36b0-efab-598d-8cc3-407f9f13fc61", "9e2536b0-988b-598d-8cc3-407f9f13fc61"], True],
        ]
)
def test_get_rules(rule_ids, should_fail):
    if should_fail:
        with pytest.raises(ValidationError):
            CorrelationRuleView().get_rules(rule_ids)
    else:
        rules = CorrelationRuleView().get_rules(rule_ids)
        assert set([r['id'][11:] for r in rules]) == set(rule_ids)
