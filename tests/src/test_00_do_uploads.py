from functools import lru_cache
import os
import time
import django
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

from tests.src.utils import is_sorted


def upload_bundles(client: django.test.Client):
    for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]:
        file = models.File.objects.create(
            name="test_file.txt",
            mimetype="text/plain",
            id=bundle["id"].replace("bundle--", ""),
        )
        job = models.Job.objects.create(file=file, id=file.id)
        tasks.upload_to_arango(job, bundle)
    time.sleep(10)

    ### modify
    for modification in [test_data.MODIFY_1, test_data.MODIFY_2]:
        indicator_id = modification['rule_id']
        resp = client.post(f'/api/v1/rules/{indicator_id}/modify/', data=modification['sigma'], content_type='application/sigma+yaml')

@pytest.mark.django_db
def test_nothing(client):
    upload_bundles(client)