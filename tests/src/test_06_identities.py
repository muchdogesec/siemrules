import django.test
from functools import lru_cache
import os
import time
import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import MagicMock, patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models, reports
from siemrules.siemrules.arangodb_helpers import request_from_queries
from siemrules.siemrules.identities import IdentityView
from siemrules.worker import tasks
from tests.src import data as test_data
from rest_framework.response import Response
from rest_framework.validators import ValidationError
from dogesec_commons.objects.helpers import ArangoDBHelper

from tests.src.utils import is_sorted

url = "/api/v1/identities/"
def test_destroy_identity(client: django.test.Client):
    identity_id = "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7"
    collected_objects = dict()

    with patch("siemrules.siemrules.models.File.objects.filter") as mock_filter_file, \
        patch('arango.database.StandardDatabase.collection') as mock_db_collection:
        delete_many: MagicMock = mock_db_collection.return_value.delete_many
        mock_filter_file_delete: MagicMock = mock_filter_file.return_value.delete
        response = client.delete(url + identity_id + "/")
        assert response.status_code == 204
        mock_filter_file.assert_called_once_with(identity__id=identity_id)
        mock_db_collection.assert_any_call("siemrules_edge_collection")
        mock_db_collection.assert_any_call("siemrules_vertex_collection")
        delete_many.assert_called()
        mock_filter_file_delete.assert_called_once()

        objects_removed = 0
        for call in delete_many.mock_calls:
            objects_removed += len(delete_many.mock_calls[0].args[0])
        assert objects_removed > 10, "at least 10 objects must have been removed"
