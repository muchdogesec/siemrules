from itertools import chain
import random
import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models
from siemrules.siemrules.views import RuleView
from siemrules.worker import tasks
from tests.src.data import BUNDLE_1
from rest_framework.response import Response

from tests.src.utils import is_sorted


@pytest.mark.django_db
class TestFileView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.file = models.File.objects.create(
            name="test_file.txt", mimetype="text/plain"
        )
        self.url = "/api/v1/files/"

    def test_list_files(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data["files"], list)
        assert len(response.data["files"]) == 1

    def test_file_create__upload(self, client):
        mock_file_content = b"dummy content"
        file_data = dict(
            file=SimpleUploadedFile(
                "test.txt", b"dummy content", content_type="text/plain"
            ),
            mode="txt",
            ai_provider="openai",
            name="dummy name",
        )
        with patch("siemrules.worker.tasks.new_task") as mock_task:
            response = client.post(
                self.url + "upload/", data=file_data, format="multipart"
            )
            assert response.status_code == status.HTTP_200_OK, response.content
            mock_task.assert_called_once()
            job: models.Job = mock_task.mock_calls[0].args[0]
            assert job.type == models.JobType.FILE
            assert job.file.file.read() == mock_file_content
            assert job.file.mode == file_data["mode"]
            assert job.file.name == file_data["name"]
            assert job.file.ai_provider == file_data["ai_provider"]
            assert 'siemrules.file' in job.file.labels, "must contain labels to differentiate from text_input"

    def test_file_create__text(self, client: django.test.Client):
        mock_file_content = b"dummy content"
        file_data = dict(
            text_input=mock_file_content.decode(), ai_provider="openai", name="dummy name"
        )
        with patch("siemrules.worker.tasks.new_task") as mock_task:
            response = client.post(
                self.url + "text/", data=file_data, content_type="application/json"
            )
            assert response.status_code == status.HTTP_200_OK, response.content
            mock_task.assert_called_once()
            job: models.Job = mock_task.mock_calls[0].args[0]
            file: models.File = job.file
            assert job.type == models.JobType.FILE
            assert file.file.read() == mock_file_content
            assert file.mode == "txt"
            assert file.name == file_data["name"]
            assert file.ai_provider == file_data["ai_provider"]
            assert 'siemrules.text' in file.labels, "must contain labels to differentiate from upload"

    def test_retrieve_file(self, client):
        response = client.get(f"{self.url}{self.file.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == str(self.file.id)

    def test_delete_file(self, client):
        with patch("siemrules.siemrules.models.File.delete") as mock_delete:
            response = client.delete(f"{self.url}{self.file.id}/")
            assert response.status_code == status.HTTP_204_NO_CONTENT
            mock_delete.assert_called_once()


@pytest.mark.django_db
class TestJobView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.file = models.File.objects.create(
            name="test_file.txt", mimetype="text/plain"
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


@pytest.mark.django_db
class TestRuleView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.url = "/api/v1/rules/"
        self.rule_id = "indicator--3f2b1a6e-8c9d-4f75-902c-2d6f88c5e3a1"
        # yield tasks.upload_to_arango(job, BUNDLE_1)

    def test_list_rules(self, client: django.test.Client):
        with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_get_rules:
            mock_get_rules.return_value = Response()
            response = client.get(self.url)
            mock_get_rules.assert_called_once()
            # mock_get_rules.assert_called_once_with(response.request, rule_type=RuleView.rule_type)
            assert mock_get_rules.mock_calls[0].kwargs['rule_type'] == RuleView.rule_type

    def test_retrieve_rule(self, client):
        with patch("siemrules.siemrules.arangodb_helpers.get_single_rule") as mock_get:
            mock_get.return_value = Response()
            response = client.get(f"{self.url}{self.rule_id}/")
            mock_get.assert_called_once()
            assert mock_get.mock_calls[0].kwargs['rule_type'] == RuleView.rule_type

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

    @pytest.mark.parametrize(
        ["rule_id", "expected_version_count"],
        [
            ["indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72", 3],
            ["indicator--8af82832-2abd-5765-903c-01d414dae1e9", 1],
            ["indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61", 1],
        ],
    )
    def test_versions(
        self, client: django.test.Client, rule_id, expected_version_count, subtests
    ):
        rule_url = f"{self.url}{rule_id}/"
        response = client.get(rule_url + "versions/")
        assert is_sorted(response.data, reverse=True), "versions must be sorted in descending order"
        assert len(response.data) == expected_version_count
        for version in chain([None], response.data):
            with subtests.test(
                "test_retrieve_with_version_param", rule_id=rule_id, version=version
            ):
                params = None
                if version:
                    params = dict(version=version)
                rule_resp = client.get(rule_url, query_params=params)
                assert rule_resp.data['id'] == rule_id
                assert rule_resp.data["modified"] == version or response.data[0]

    
    def test_revert_rule(self, client: django.test.Client):
        rule_id = "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72"
        rule_url = f"{self.url}{rule_id}/"

        versions = client.get(rule_url + "versions/").data
        expected_version = random.choice(versions)
        response = client.patch(rule_url + "revert/", data=dict(version=expected_version), content_type="application/json")
        assert response.data['modified'] == expected_version
        response = client.patch(rule_url)
        assert response.data['modified'] == expected_version

