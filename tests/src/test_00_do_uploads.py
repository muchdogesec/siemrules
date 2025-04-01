from functools import lru_cache
from itertools import chain
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


def upload_bundles():
    for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]:
        file = models.File.objects.create(
            name="test_file.txt",
            mimetype="text/plain",
            id=bundle["id"].replace("bundle--", ""),
        )
        job = models.Job.objects.create(file=file, id=file.id)
        tasks.upload_to_arango(job, bundle)
    time.sleep(10)

def all_objects():
    bundle_objects = [bundle['objects'] for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]]
    return [obj for obj in chain(*bundle_objects) if obj['type'] != 'relationship']

@pytest.mark.django_db
def test_nothing():
        upload_bundles()

@pytest.mark.parametrize(
    'modification',
    [test_data.MODIFY_1, test_data.MODIFY_2]
)
def test_modify_rule(client: django.test.Client, modification):
    indicator_id = modification['rule_id']
    indicator = [obj for obj in all_objects() if obj['id'] == indicator_id][0]
    indicator_refs = [x['external_id'] for x in indicator['external_references']]
    with patch('txt2detection.bundler.Bundler.get_attack_objects') as get_attack_objects, patch('txt2detection.bundler.Bundler.get_cve_objects') as get_cve_objects:
        get_attack_objects.return_value = [obj for obj in all_objects() if obj['type'] != 'indicator' and obj.get('external_references') and obj['external_references'][0]['external_id'] in indicator_refs and obj['external_references'][0]['source_name'] == 'mitre-attack']
        get_cve_objects.return_value = [obj for obj in all_objects() if obj['type'] != 'indicator' and obj.get('external_references') and obj['external_references'][0]['external_id'] in indicator_refs and obj['external_references'][0]['source_name'] == 'cve']
        resp = client.post(f'/api/v1/rules/{indicator_id}/modify/', data=modification['sigma'], content_type='application/sigma+yaml')