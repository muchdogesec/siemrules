from functools import lru_cache
import time
import django
import pytest
from llama_index.core.program import LLMTextCompletionProgram


import django.test
from unittest.mock import MagicMock, patch
import yaml
from siemrules.siemrules.correlations.correlations import yaml_to_rule
from siemrules.siemrules.correlations.models import RuleModel
from siemrules.siemrules.serializers import FileSigmaYamlSerializer
from siemrules.worker import tasks
from tests.src import data as test_data


import time
import django
import pytest

import django.test
from unittest.mock import patch
from siemrules.worker import tasks
from tests.src import data as test_data


@lru_cache
def upload_identities():
    tasks.upload_objects(MagicMock(), dict(objects=test_data.identities, type='bundle', id='bundle--identities'), {})
    time.sleep(5)


@pytest.mark.parametrize(
    ["rule_id", "sigma_yaml"],
    [
        pytest.param(*test_data.SIGMA_RULE_1, id="item 1"),
        pytest.param(*test_data.SIGMA_RULE_2, id="item 2"),
        pytest.param(*test_data.SIGMA_RULE_3, id="item 3"),
    ]
)
@pytest.mark.django_db
def test_make_uploads(client, celery_eager, rule_id, sigma_yaml):
    upload_identities()

    save_model = FileSigmaYamlSerializer.save
    with patch(
        "txt2detection.bundler.Bundler.get_attack_objects", side_effect=lambda attack_ids: [v for k,v in test_data.objects_lookup.items() if k in attack_ids]
    ) as get_attack_objects, patch(
        "txt2detection.bundler.Bundler.get_cve_objects", side_effect=lambda cve_ids: [v for k,v in test_data.objects_lookup.items() if k in cve_ids]
    ) as get_cve_objects, patch.object(FileSigmaYamlSerializer, "save", autospec=True, side_effect=lambda *x, **t: save_model(*x, **{**t, "id":rule_id})):
        resp = client.post(
            f"/api/v1/files/yml/",
            data=sigma_yaml,
            content_type="application/sigma+yaml",
        )
        assert resp.status_code == 201, resp.json()

        job_resp = client.get(f"/api/v1/jobs/{resp.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data['state'] == 'completed'


@pytest.mark.django_db
@pytest.mark.parametrize("modification", [test_data.MODIFY_1, test_data.MODIFY_2])
def test_modify_base_rule_manual(
    celery_eager, client: django.test.Client, modification
):
    indicator_id = modification["rule_id"]
    with patch(
        "txt2detection.bundler.Bundler.get_attack_objects", side_effect=lambda attack_ids: [v for k,v in test_data.objects_lookup.items() if k in attack_ids]
    ) as get_attack_objects, patch(
        "txt2detection.bundler.Bundler.get_cve_objects", side_effect=lambda cve_ids: [v for k,v in test_data.objects_lookup.items() if k in cve_ids]
    ) as get_cve_objects:
        resp = client.post(
            f"/api/v1/base-rules/{indicator_id}/modify/yml/",
            data=modification["sigma"],
            content_type="application/sigma+yaml",
        )
        assert resp.status_code == 201, resp.json()

        job_resp = client.get(f"/api/v1/jobs/{resp.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data['state'] == 'completed'

correlation_url = "/api/v1/correlation-rules/"
@pytest.mark.parametrize("rule", [test_data.CORRELATION_RULE_1, test_data.CORRELATION_RULE_2])
@pytest.mark.django_db
def test_upload_correlation(celery_eager, client, rule):
    rule_id, rule = rule

    with patch.object(RuleModel, "_rule_id", rule_id):
        response = client.post(
            correlation_url + "create/yml/",
            format="sigma",
            data=rule,
            content_type="application/sigma+yaml",
        )
        assert response.status_code == 200
        resp = client.get(correlation_url + f"indicator--{rule_id}/")
        assert resp.status_code == 200

@pytest.mark.django_db
@pytest.mark.parametrize(
    ["rule_id", "modification"],
    [
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(title="new title", description="new_description"),
        ]
    ]
)
def test_modify_correlation_manual(celery_eager, client, rule_id, modification):
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
    assert job_resp.data['state'] == 'completed'
    indicator = client.get(
        correlation_url + rule_id + '/'
    ).data
    if expected_descr := modification.get('description'):
        assert indicator['description'] == expected_descr
    
    if expected_name := modification.get('title'):
        assert indicator['name'] == expected_name


@pytest.mark.django_db
@pytest.mark.parametrize(
    ["rule_id", "modification"],
    [
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(description="ai generated description"),
        ],
        [
            "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            dict(tags=['some.other_tag']),
        ]
    ]
)
def test_modify_correlation_rule_from_prompt(celery_eager, client, rule_id, modification):
    url = correlation_url
    indicator = client.get(
        url + rule_id + '/'
    ).data
    rule, _ = yaml_to_rule(indicator['pattern'])
    ai_modification = rule.model_copy(update=modification)
    with patch.object(LLMTextCompletionProgram, '__call__', new=MagicMock(return_value=ai_modification)) as mock_ai_call:
        response = client.post(
            url + f"{rule_id}/modify/prompt/",
            data={'ai_provider': 'openai', 'prompt': 'some prompt'},
            content_type='application/json'
        )
        assert response.status_code == 201
        job_resp = client.get(f"/api/v1/jobs/{response.data['id']}/")
        assert job_resp.status_code == 200
        assert job_resp.data['state'] == 'completed', job_resp.data
        indicator = client.get(
            url + rule_id + '/'
        ).data
        rule, _ = yaml_to_rule(indicator['pattern'])

        if expected_descr := modification.get('description'):
            assert indicator['description'] == expected_descr
            assert rule.description == expected_descr
        assert indicator['name'] == ai_modification.title
        if expected_tags := modification.get('tags'):
            assert set(expected_tags).issubset(rule.tags)