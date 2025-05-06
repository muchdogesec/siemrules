import copy
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

from functools import lru_cache
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
from siemrules.worker import tasks
from tests.src import data as test_data
from rest_framework.response import Response
from rest_framework.validators import ValidationError

from siemrules.siemrules.arangodb_helpers import RULES_SORT_FIELDS, get_rules, get_single_rule, delete_rule
from rest_framework.exceptions import NotFound
from rest_framework.request import Request

from tests.src.utils import is_sorted


def upload_bundles():
    for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]:
        file = models.File.objects.create(
            name="test_file.txt",
            mimetype="text/plain",
            id=bundle["id"].replace("bundle--", ""),
        )
        job = models.Job.objects.create(file=file, id=file.id)
        tasks.upload_to_arango(job, copy.deepcopy(bundle))
    time.sleep(5)

def all_objects():
    bundle_objects = [bundle['objects'] for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]]
    bundle_objects = copy.deepcopy(bundle_objects)
    return [obj for obj in chain(*bundle_objects) if obj['type'] != 'relationship']

@pytest.mark.django_db
def test_make_uploads():
    upload_bundles()

@pytest.mark.django_db
@pytest.mark.parametrize(
    'modification',
    [test_data.MODIFY_1, test_data.MODIFY_2]
)
def test_modify_rule(client: django.test.Client, modification):
    indicator_id = modification['rule_id']
    indicator = [obj for obj in all_objects() if obj['id'] == indicator_id][0]
    indicator_refs = [x['external_id'] for x in indicator['external_references']]
    time.sleep(2)
    with patch('txt2detection.bundler.Bundler.get_attack_objects') as get_attack_objects, patch('txt2detection.bundler.Bundler.get_cve_objects') as get_cve_objects:
        get_attack_objects.return_value = [obj for obj in all_objects() if obj['type'] != 'indicator' and obj.get('external_references') and obj['external_references'][0]['external_id'] in indicator_refs and obj['external_references'][0]['source_name'] == 'mitre-attack']
        get_cve_objects.return_value = [obj for obj in all_objects() if obj['type'] != 'indicator' and obj.get('external_references') and obj['external_references'][0]['external_id'] in indicator_refs and obj['external_references'][0]['source_name'] == 'cve']
        resp = client.post(f'/api/v1/rules/{indicator_id}/modify/base-rule/manual/', data=modification['sigma'], content_type='application/sigma+yaml')
        assert resp.status_code == 200, resp.json()
        time.sleep(1)
