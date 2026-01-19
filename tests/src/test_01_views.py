from itertools import chain
import random
import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import arangodb_helpers, models
from rest_framework.response import Response

from tests.src.utils import is_sorted
from tests.utils import Transport


class TestFileView:
    @pytest.fixture(autouse=True)
    def setup(self, profile):
        self.file = models.File.objects.create(
            name="test_file.txt", mimetype="text/plain", profile=profile, identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63"
        )
        self.url = "/api/v1/files/"

    def test_list_files(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data["files"], list)
        assert len(response.data["files"]) == 1

    def test_file_create__upload(self, client, profile):
        mock_file_content = b"dummy content"
        file_data = dict(
            file=SimpleUploadedFile(
                "test.txt", b"dummy content", content_type="text/plain"
            ),
            mode="txt",
            name="dummy name",
            profile_id=profile.id,
        )
        with patch("siemrules.worker.tasks.new_task") as mock_task:
            response = client.post(
                self.url + "intel/", data=file_data, format="multipart"
            )
            assert response.status_code == status.HTTP_201_CREATED, response.content
            mock_task.assert_called_once()
            job: models.Job = mock_task.mock_calls[0].args[0]
            assert job.type == models.JobType.FILE_FILE
            assert job.file.file.read() == mock_file_content
            assert job.file.mode == file_data["mode"]
            assert job.file.name == file_data["name"]
            assert job.profile == profile

    def test_file_create__text(self, client: django.test.Client, profile):
        mock_file_content = b"dummy content"
        file_data = dict(
            text_input=mock_file_content.decode(),
            ai_provider="openai",
            name="dummy name",
            profile_id=profile.id,
        )
        with patch("siemrules.worker.tasks.new_task") as mock_task:
            response = client.post(
                self.url + "prompt/", data=file_data, content_type="application/json"
            )
            assert response.status_code == status.HTTP_201_CREATED, response.content
            mock_task.assert_called_once()
            job: models.Job = mock_task.mock_calls[0].args[0]
            file: models.File = job.file
            assert job.type == models.JobType.FILE_TEXT
            assert file.file.read() == mock_file_content
            assert file.mode == "txt"
            assert file.name == file_data["name"]
            assert file.profile == profile

    def test_retrieve_file(self, client):
        response = client.get(f"{self.url}{self.file.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == str(self.file.id)

    def test_delete_file(self, client):
        with patch("siemrules.siemrules.models.File.delete") as mock_delete:
            response = client.delete(f"{self.url}{self.file.id}/")
            assert response.status_code == status.HTTP_204_NO_CONTENT
            mock_delete.assert_called_once()

    def test_processing_log(self, client, job, api_schema):
        job.file.txt2detection_data = {"some_new": "data"}
        job.file.save()
        response = client.get(f"{self.url}{job.file.id}/processing-log/")
        assert response.json() == {"some_new": "data"}
        assert response.status_code == 200
        api_schema["/api/v1/files/{file_id}/processing-log/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )


class TestJobView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.file = models.File.objects.create(
            name="test_file.txt", mimetype="text/plain",
            identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
        )
        self.job = models.Job.objects.create(file=self.file)
        self.url = "/api/v1/jobs/"

    def test_list_jobs(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data["jobs"], list)
        assert len(response.data["jobs"]) == 1

    def test_retrieve_job(self, client):
        response = client.get(f"{self.url}{self.job.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == str(self.job.id)


class TestBaseRuleView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.url = "/api/v1/base-rules/"
        self.rule_id = "indicator--3f2b1a6e-8c9d-4f75-902c-2d6f88c5e3a1"
        # yield tasks.upload_to_arango(job, BUNDLE_1)

    def test_list_rules(self, client: django.test.Client):
        with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_get_rules:
            mock_get_rules.return_value = Response()
            response = client.get(self.url)
            assert response.status_code == 200
            mock_get_rules.assert_called_once()

    def test_retrieve_rule(self, client):
        with patch("siemrules.siemrules.arangodb_helpers.get_single_rule") as mock_get:
            mock_get.return_value = Response()
            response = client.get(f"{self.url}{self.rule_id}/")
            mock_get.assert_called_once()

    @pytest.mark.parametrize(
        ["format", "expected_content_type"],
        [
            (None, "application/json"),  # default
            ("json", "application/json"),
            ("sigma", "application/sigma+yaml"),
        ],
    )
    def test_retrieve_rule_with_format(self, client, format, expected_content_type):
        rule_url = f"{self.url}{self.rule_id}/"
        with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_queryset:
            params = None
            if format:
                params = dict(format=format)
            mock_sigma_rule_pattern = "sigma rule here"
            mock_queryset.return_value = [dict(pattern=mock_sigma_rule_pattern)]
            response = client.get(rule_url, query_params=params)
            mock_queryset.assert_called_once()
            assert response.headers["content-type"] == expected_content_type
            if format == "sigma":
                assert response.content.decode() == mock_sigma_rule_pattern

    def test_revert_rule(self, client: django.test.Client, celery_eager):
        rule_id = "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"
        rule_url = f"{self.url}{rule_id}/"

        versions_resp = arangodb_helpers.get_single_rule_versions(
            rule_id, 'base'
        )
        assert versions_resp.status_code == 200, versions_resp.json()
        versions_before_revert = list(versions_resp.data)
        revert_version = random.choice(versions_before_revert[1:])
        object_before_revert = client.get(
            rule_url, query_params=dict(version=revert_version)
        ).json()

        response = client.patch(
            rule_url + "modify/revert/",
            data=dict(version=revert_version),
            content_type="application/json",
        )
        assert response.status_code == 201, response.json()
        object_after_revert = client.get(rule_url).json()
        assert object_after_revert["modified"] > max(
            versions_before_revert
        ), "object_after_revert must be newer than all previously existing objects"

        versions_resp = arangodb_helpers.get_single_rule_versions(
            rule_id, 'base'
        )
        assert versions_resp.status_code == 200, versions_resp.json()
        versions_after_revert = list(versions_resp.data)
        assert (
            len(versions_after_revert) == len(versions_before_revert) + 1
        ), "count(versions_after_revert) must be count(versions_before_revert)+1"
        assert set(versions_after_revert).issuperset(
            versions_before_revert
        ), "versions_after_revert must be a superset of versions_before_revert"

        for k in object_before_revert.keys():
            if k in ["external_references", "modified", 'pattern']:
                continue
            assert object_before_revert[k] == object_after_revert[k]


        ## test revert in list
        versions_resp = client.get(rule_url + "versions/")
        assert {'action': 'modify', 'modified': object_after_revert['modified'], 'base_version': object_before_revert['modified'], 'type': 'revert'} in versions_resp.data

    def test_revert_to_latest(self, client: django.test.Client):
        rule_id = "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"
        rule_url = f"{self.url}{rule_id}/"

        versions_resp = arangodb_helpers.get_single_rule_versions(
            rule_id, 'base'
        )
        assert versions_resp.status_code == 200, versions_resp.json()
        versions_before_revert = list(versions_resp.data)
        revert_version = versions_before_revert[0]  # latest version

        response = client.patch(
            rule_url + "modify/revert/",
            data=dict(version=revert_version),
            content_type="application/json",
        )
        assert response.status_code == 400, response.json()

    def test_revert_bad_version(self, client: django.test.Client):
        rule_id = "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"
        rule_url = f"{self.url}{rule_id}/"

        revert_version = "2001-01-01T01:01:01.001Z"  # bad version

        response = client.patch(
            rule_url + "modify/revert/",
            data=dict(version=revert_version),
            content_type="application/json",
        )
        assert response.status_code == 400, response.json()


def test_retrieve_profile(profile, client):
    resp = client.get(f"/api/v1/profiles/{profile.id}/")
    assert resp.status_code == 200
    assert resp.json()["id"] == str(profile.id)


def test_default_profile():
    file = models.File.objects.create(name="test_file.txt", mimetype="text/plain", identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63")
    assert file.profile == file.profile.default_profile()


def test_regular_profile_does_not_use_default_profile(profile, default_profile):
    default_profile.is_default = True
    default_profile.save()

    file = models.File.objects.create(
        name="test_file.txt", mimetype="text/plain", profile=profile, identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    )
    assert file.profile == profile


def test_create_profile(client):
    payload = {
        "ai_provider": "anthropic:claude-sonnet-4-5",
        "include_embedded_relationships_attributes": [],
        "generate_pdf": True,
        "name": "test_profile 3",
        "extract_text_from_image": True,
    }

    resp = client.post(
        f"/api/v1/profiles/", data=payload, content_type="application/json"
    )
    assert resp.status_code == 201, resp.content
    data = resp.json()
    del data['created']
    assert data == {
        "id": "cf51da4a-296f-5b4d-adc9-a80a26990cd4",
        "ai_provider": "anthropic:claude-sonnet-4-5",
        "ignore_embedded_relationships": False,
        "ignore_embedded_relationships_sro": False,
        "ignore_embedded_relationships_smo": False,
        "include_embedded_relationships_attributes": [],
        "generate_pdf": True,
        "name": "test_profile 3",
        "extract_text_from_image": True,
        "is_default": False,
    }
    if not resp.json()["is_default"]:
        resp = client.patch(f"/api/v1/profiles/{data['id']}/make_default/")
        assert resp.json()["is_default"] == True


def test_list_profile(profile, client):
    resp = client.get(f"/api/v1/profiles/")
    assert resp.status_code == 200
    assert resp.json()["profiles"][0]["id"] == str(profile.id)


def test_profile_extractors(client):
    resp = client.get(f"/api/v1/profiles/extractors/")
    assert resp.status_code == 200
    assert set(resp.json()).issuperset(["ipv4-addr", "ipv6-addr"])


def test_healthcheck(client):
    resp = client.get("/api/healthcheck/")
    assert resp.status_code == 204


def test_healthcheck_service(client, api_schema):
    resp = client.get("/api/healthcheck/service/")
    assert resp.status_code == 200
    api_schema["/api/healthcheck/service/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )


class TestDataSourceView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.url = "/api/v1/data-sources/"

    @pytest.mark.parametrize(
        ["params", "expected_ids"],
        [
            pytest.param(dict(), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2", "data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a", "data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="no_filter"),
            pytest.param(dict(product="application"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2", "data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="product_full"),
            pytest.param(dict(product="PliCation"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2", "data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="product_partial_bad_case"),
            pytest.param(dict(product="app"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2", "data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="product_partial"),
            pytest.param(dict(product="wordpress"), ["data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="product_wordpress"),
            pytest.param(dict(product="nonexistent"), [], id="product_no_match"),
            pytest.param(dict(service="xz"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="service_xz"),
            pytest.param(dict(service="XZ"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="service_xz_bad_case"),
            pytest.param(dict(service="x"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="service_partial"),
            pytest.param(dict(service="nonexistent"), [], id="service_no_match"),
            pytest.param(dict(category="file"), ["data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="category_file"),
            pytest.param(dict(category="ILe"), ["data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="category_bad_case"),
            pytest.param(dict(category="webserver"), ["data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="category_webserver"),
            pytest.param(dict(category="web"), ["data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="category_partial"),
            pytest.param(dict(category="nonexistent"), [], id="category_no_match"),
            pytest.param(dict(definition="file system"), ["data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="definition_file_system"),
            pytest.param(dict(definition="logs"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2", "data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="definition_logs"),
            pytest.param(dict(definition="web server"), ["data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="definition_web_server"),
            pytest.param(dict(definition="compression"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="definition_compression"),
            pytest.param(dict(definition="PREss"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="definition_compression_bad_case"),
            pytest.param(dict(definition="nonexistent"), [], id="definition_no_match"),
            pytest.param(dict(product="application", service="xz"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="multi_product_service"),
            pytest.param(dict(product="wordpress", category="webserver"), ["data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a"], id="multi_product_category"),
            pytest.param(dict(category="file", definition="file system"), ["data-source--34ad2f90-179a-567e-8867-e527f5a3219b"], id="multi_category_definition"),
            pytest.param(dict(product="application", service="xz", definition="compression"), ["data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2"], id="multi_all_fields"),
            pytest.param(dict(product="application", service="nonexistent"), [], id="multi_conflicting"),
        ],
    )
    def test_filters(self, client, params, expected_ids):
        """Test data-source filtering with various parameter combinations"""
        response = client.get(self.url, query_params=params)
        data_source_ids = [ds["id"] for ds in response.data["data_sources"]]
        assert set(data_source_ids) == set(expected_ids)
        assert response.status_code == 200

    def test_list_data_sources(self, client):
        """Test basic data-source listing"""
        with patch("siemrules.siemrules.arangodb_helpers.get_data_sources") as mock_get:
            mock_get.return_value = Response({"data_sources": []})
            response = client.get(self.url)
            assert response.status_code == 200
            mock_get.assert_called_once()