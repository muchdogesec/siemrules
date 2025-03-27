import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models
from siemrules.worker import tasks
from tests.src.data import BUNDLE_1
from rest_framework.response import Response

@pytest.mark.django_db
class TestFileView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.file = models.File.objects.create(name="test_file.txt", mimetype="text/plain")
        self.url = "/api/v1/files/"

    def test_list_files(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data['files'], list)
        assert len(response.data['files']) == 1

    def test_upload_file(self, client):
        file_data = dict(file=SimpleUploadedFile("test.txt", b"dummy content", content_type="text/plain"), mode="txt", ai_provider="openai", name='dummy name')
        with patch("siemrules.worker.tasks.new_task") as mock_task:
            response = client.post(self.url, data=file_data, format='multipart')
            assert response.status_code == status.HTTP_200_OK, response.content
            mock_task.assert_called_once()

    def test_retrieve_file(self, client):
        response = client.get(f"{self.url}{self.file.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(self.file.id)

    def test_delete_file(self, client):
        with patch("siemrules.siemrules.models.File.delete") as mock_delete:
            response = client.delete(f"{self.url}{self.file.id}/")
            assert response.status_code == status.HTTP_204_NO_CONTENT
            mock_delete.assert_called_once()

@pytest.mark.django_db
class TestJobView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.file = models.File.objects.create(name="test_file.txt", mimetype="text/plain")
        self.job = models.Job.objects.create(file=self.file)
        self.url = "/api/v1/jobs/"

    def test_list_jobs(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data['jobs'], list)
        assert len(response.data['jobs']) == 1

    def test_retrieve_job(self, client):
        response = client.get(f"{self.url}{self.job.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(self.job.id)

class TestRuleView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.url = "/api/v1/rules/"
        self.rule_id = "indicator--3f2b1a6e-8c9d-4f75-902c-2d6f88c5e3a1"
        # yield tasks.upload_to_arango(job, BUNDLE_1)

    def test_list_rules(self, client: django.test.Client):
        with patch("siemrules.siemrules.arangodb_helpers.get_rules") as mock_queryset:
            mock_queryset.return_value = Response()
            response = client.get(self.url)
            mock_queryset.assert_called_once()

    def test_retrieve_rule(self, client):
        with patch("siemrules.siemrules.arangodb_helpers.get_single_rule") as mock_get:
            mock_get.return_value = Response()
            response = client.get(f"{self.url}{self.rule_id}/")
            mock_get.assert_called_once()
