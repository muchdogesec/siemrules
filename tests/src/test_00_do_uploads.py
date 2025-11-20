from datetime import UTC, datetime
from functools import lru_cache
import time
import django
import pytest
from llama_index.core.program import LLMTextCompletionProgram


import django.test
from unittest.mock import MagicMock, patch
import yaml
from siemrules.siemrules import models
from siemrules.siemrules.correlations.correlations import yaml_to_rule
from siemrules.siemrules.correlations.models import RuleModel
from siemrules.siemrules.modifier import yaml_to_detection
from siemrules.siemrules.serializers import FileSigmaYamlSerializer
from siemrules.worker import tasks
from tests.src import data as test_data
from txt2detection.models import SigmaRuleDetection


import time
import django
import pytest

import django.test
from unittest.mock import patch
from siemrules.worker import tasks
from tests.src import data as test_data
from tests.utils import Transport


@pytest.fixture(autouse=True)
def db_access_without_rollback_and_truncate(request, django_db_setup, django_db_blocker):
    django_db_blocker.unblock()
    yield
    django_db_blocker.restore()

@pytest.mark.parametrize(
    ["rule_id", "sigma_yaml"],
    [
        pytest.param(*test_data.SIGMA_RULE_1, id="item 1"),
    ],
)
def test_base_yml_upload(client, celery_eager, rule_id, sigma_yaml, api_schema):
    save_model = FileSigmaYamlSerializer.save
    with patch.object(
        FileSigmaYamlSerializer,
        "save",
        autospec=True,
        side_effect=lambda *x, **t: save_model(*x, **{**t, "id": rule_id}),
    ):
        resp = client.post(
            f"/api/v1/files/yml/",
            data=sigma_yaml,
            content_type="application/sigma+yaml",
        )
        assert resp.status_code == 201, resp.json()

        job_resp = client.get(f"/api/v1/jobs/{resp.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data["state"] == "completed"

        version_resp = client.get(f'/api/v1/base-rules/indicator--{rule_id}/versions/')
        api_schema['/api/v1/base-rules/{indicator_id}/versions/'][
        "GET"
        ].validate_response(Transport.get_st_response(version_resp))
        assert {'modified': '2024-05-01T00:00:00.000Z', 'action': 'create', 'type': 'sigma', 'file_id': rule_id} in version_resp.data
        assert models.File.objects.get(pk=rule_id).file.read().decode() == sigma_yaml

@pytest.mark.parametrize(
    ["rule_id", "tlp_level", "sigma_yaml"],
    [
        pytest.param(*test_data.SIGMA_RULE_2, id="item 2"),
        pytest.param(*test_data.SIGMA_RULE_3, id="item 3"),
    ],
)
def test_base_prompt_upload(client, profile, celery_eager, rule_id, tlp_level, sigma_yaml, api_schema):
    profile.ai_provider = "openai"
    profile.save()
    from txt2detection.ai_extractor.base import BaseAIExtractor
    from txt2detection.models import DetectionContainer
    detection = yaml_to_detection(sigma_yaml)
    detection.detection_id = rule_id
    with patch.object(BaseAIExtractor, "get_detections") as mock_get_detections:
        mock_get_detections.return_value = DetectionContainer(success=True, detections=[detection])
        resp = client.post(
            f"/api/v1/files/prompt/",
            data=dict(
                name=detection.title,
                tlp_level=tlp_level,
                text_input=f"some prompt;; {detection.description}",
                profile_id=profile.id,
                report_id=f"report--{rule_id}",
            ),
            content_type="application/json",
        )
        assert resp.status_code == 201, resp.json()

        job_resp = client.get(f"/api/v1/jobs/{resp.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data["state"] == "completed"
        assert job_resp.data['file_id'] == rule_id


        version_resp = client.get(f'/api/v1/base-rules/indicator--{rule_id}/versions/')
        api_schema['/api/v1/base-rules/{indicator_id}/versions/'][
        "GET"
        ].validate_response(Transport.get_st_response(version_resp))
        assert version_resp.data[0]['action'] == 'create'
        assert version_resp.data[0]['file_id'] == rule_id
        assert version_resp.data[0]['type'] == 'prompt'

@pytest.mark.parametrize("modification", [test_data.MODIFY_1, test_data.MODIFY_2])
def test_modify_base_rule_manual(
    celery_eager, client: django.test.Client, modification, api_schema
):
    base_time = datetime.now(UTC)
    indicator_id = modification["rule_id"]

    resp = client.post(
        f"/api/v1/base-rules/{indicator_id}/modify/yml/",
        data=modification["sigma"],
        content_type="application/sigma+yaml",
    )
    assert resp.status_code == 201, resp.json()

    job_resp = client.get(f"/api/v1/jobs/{resp.data['id']}/")
    assert job_resp.status_code == 200
    assert job_resp.data["state"] == "completed"

    resp = client.get(
        f"/api/v1/base-rules/{indicator_id}/",
    )
    assert resp.status_code == 200
    assert resp.data["modified"] > base_time.isoformat()
    assert resp.data["modified"] == job_resp.data["extra"]["resultant_version"]


    version_resp = client.get(f'/api/v1/base-rules/{indicator_id}/versions/')
    api_schema['/api/v1/base-rules/{indicator_id}/versions/'][
    "GET"
    ].validate_response(Transport.get_st_response(version_resp))
    assert {'modified': version_resp.data[0]['modified'], 'action': 'modify', 'type': 'sigma'} in version_resp.data

correlation_url = "/api/v1/correlation-rules/"


@pytest.mark.parametrize(
    "rule", [test_data.CORRELATION_RULE_1, test_data.CORRELATION_RULE_2]
)
def test_upload_correlation(celery_eager, client, rule, api_schema):
    rule_id, rule = rule

    with patch.object(RuleModel, "_rule_id", rule_id):
        job_resp = client.post(
            correlation_url + "create/yml/",
            format="sigma",
            data=rule,
            content_type="application/sigma+yaml",
        )
        assert job_resp.status_code == 200

        resp = client.get(correlation_url + f"indicator--{rule_id}/")
        assert resp.status_code == 200
        file = models.Job.objects.get(id=job_resp.data['id']).file
        assert file.file.read().decode() == rule

    version_resp = client.get(f'/api/v1/correlation-rules/indicator--{rule_id}/versions/')
    api_schema['/api/v1/correlation-rules/{indicator_id}/versions/'][
    "GET"
    ].validate_response(Transport.get_st_response(version_resp))
    assert {'modified': version_resp.data[0]['modified'], 'action': 'create', 'type': 'sigma', 'file_id': str(file.id)} in version_resp.data

@pytest.mark.parametrize(
    ["rule_id", "modification"],
    [
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(title="new title", description="new_description"),
        ]
    ],
)
def test_modify_correlation_manual(celery_eager, client, rule_id, modification, api_schema):
    modification_yaml = yaml.safe_dump(modification)
    response = client.post(
        correlation_url + f"{rule_id}/modify/yml/",
        format="sigma",
        data=modification_yaml,
        content_type="application/sigma+yaml",
    )
    assert response.status_code == 201
    job_resp = client.get(f"/api/v1/jobs/{response.data['id']}/")
    assert job_resp.status_code == 200
    assert job_resp.data["state"] == "completed"
    indicator = client.get(correlation_url + rule_id + "/").data
    if expected_descr := modification.get("description"):
        assert indicator["description"] == expected_descr

    if expected_name := modification.get("title"):
        assert indicator["name"] == expected_name

    assert indicator["modified"] == job_resp.data["extra"]["resultant_version"]

    version_resp = client.get(f'/api/v1/correlation-rules/{rule_id}/versions/')
    api_schema['/api/v1/correlation-rules/{indicator_id}/versions/'][
    "GET"
    ].validate_response(Transport.get_st_response(version_resp))
    print(version_resp.content)
    assert {'modified': version_resp.data[0]['modified'], 'action': 'modify', 'type': 'sigma'} in version_resp.data

@pytest.mark.parametrize(
    ["rule_id", "modification"],
    [
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(description="ai generated description"),
        ],
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(tags=["some.other_tag"]),
        ],
    ],
)
def test_modify_correlation_rule_from_prompt(
    celery_eager, client, rule_id, modification, api_schema
):
    url = correlation_url
    indicator = client.get(url + rule_id + "/").data
    rule, _ = yaml_to_rule(indicator["pattern"])
    ai_modification = rule.model_copy(update=modification)
    with patch.object(
        LLMTextCompletionProgram,
        "__call__",
        new=MagicMock(return_value=ai_modification),
    ) as mock_ai_call:
        response = client.post(
            url + f"{rule_id}/modify/prompt/",
            data={"ai_provider": "openai", "prompt": "some prompt"},
            content_type="application/json",
        )
        assert response.status_code == 201
        job_resp = client.get(f"/api/v1/jobs/{response.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data["state"] == "completed", job_resp.data
        indicator = client.get(url + rule_id + "/").data
        rule, _ = yaml_to_rule(indicator["pattern"])

        if expected_descr := modification.get("description"):
            assert indicator["description"] == expected_descr
            assert rule.description == expected_descr
        assert indicator["name"] == ai_modification.title
        if expected_tags := modification.get("tags"):
            assert set(expected_tags).issubset(rule.tags)

    assert indicator["modified"] == job_resp.data["extra"]["resultant_version"]

    version_resp = client.get(f'/api/v1/correlation-rules/{rule_id}/versions/')
    api_schema['/api/v1/correlation-rules/{indicator_id}/versions/'][
    "GET"
    ].validate_response(Transport.get_st_response(version_resp))
    assert {'modified': version_resp.data[0]['modified'], 'action': 'modify', 'type': 'prompt', "prompt": "some prompt"} in version_resp.data