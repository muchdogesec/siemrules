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


@pytest.mark.django_db
class TestReportsView:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.url = "/api/v1/reports/"
        self.report_id = "report--3f2b1a6e-8c9d-4f75-902c-2d6f88c5e3a1"

    def test_retrieve(self, client):
        with patch(
            "siemrules.siemrules.reports.ArangoDBHelper.get_objects_by_id"
        ) as mock_get_object:
            mock_get_object.return_value = Response()
            response = client.get(self.url + self.report_id + "/")
            mock_get_object.assert_called_once_with(self.report_id)

    def test_objects_list(self, client):
        with patch(
            "siemrules.siemrules.reports.ReportView.get_report_objects"
        ) as mock_get_report_objects:
            mock_get_report_objects.return_value = Response()
            response = client.get(self.url + self.report_id + "/objects/")
            mock_get_report_objects.assert_called_once_with(self.report_id)

    def test_list(self, client):
        with patch(
            "siemrules.siemrules.reports.ReportView.get_reports"
        ) as mock_get_reports:
            mock_get_reports.return_value = Response()
            response = client.get(self.url)
            mock_get_reports.assert_called_once()

    def test_path_param_as_report_id(self):
        assert reports.ReportView.path_param_as_report_id("value") == "report--value"
        assert (
            reports.ReportView.path_param_as_report_id("some-other-value")
            == "report--some-other-value"
        )
        assert (
            reports.ReportView.path_param_as_report_id("report-value")
            == "report--report-value"
        )
        assert (
            reports.ReportView.path_param_as_report_id("report--value")
            == "report--value"
        )

    def test_path_param_as_uuid(self, subtests):
        with subtests.test("invalid uuid part"), pytest.raises(ValidationError):
            reports.ReportView.path_param_as_uuid("report--value")

        with subtests.test("invalid type and uuid part"), pytest.raises(
            ValidationError
        ):
            reports.ReportView.path_param_as_uuid("indicator--value")

        with subtests.test("invalid type part"), pytest.raises(ValidationError):
            reports.ReportView.path_param_as_uuid(
                "indicator--3f2b1a6e-8c9d-4f75-902c-2d6f88c5e3a1"
            )

        assert (
            reports.ReportView.path_param_as_uuid(
                "report--abcdef12-8c9d-4f75-902c-2d6f88c5e3a1"
            )
            == "abcdef12-8c9d-4f75-902c-2d6f88c5e3a1"
        )
        assert (
            reports.ReportView.path_param_as_uuid(
                "report--bcdef12a-8c9d-4f75-902c-2d6f88c5e3a1"
            )
            == "bcdef12a-8c9d-4f75-902c-2d6f88c5e3a1"
        )
        assert (
            reports.ReportView.path_param_as_uuid(
                "report--cdef12ab-8c9d-4f75-902c-2d6f88c5e3a1"
            )
            == "cdef12ab-8c9d-4f75-902c-2d6f88c5e3a1"
        )

    def test_destroy(self, client):
        file = models.File.objects.create(
            name="test_file.txt",
            mimetype="text/plain",
            id=reports.ReportView.path_param_as_uuid(self.report_id),
        )
        with patch("siemrules.siemrules.models.File.objects.filter") as mock_filter:
            mock_delete = mock_filter.return_value.delete
            mock_delete.return_value = None
            response = client.delete(f"{self.url}{self.report_id}/")
            assert response.status_code == status.HTTP_204_NO_CONTENT
            mock_delete.assert_called_once()
            mock_filter.assert_called_once_with(
                id=reports.ReportView.path_param_as_uuid(self.report_id)
            )

    @pytest.mark.parametrize(
        ["filters", "expected_ids"],
        [
            pytest.param(
                dict(),
                [
                    "report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                    "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
                ],
                id='no filter'
            ),
            pytest.param(dict(created_min="2027-01-01"), []),
            pytest.param(
                dict(created_min="2001-01-01"),
                [
                    "report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                    "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
                ],
                id='created_min 1',
            ),
            pytest.param(
                dict(created_min="2025-03-01"),
                [
                    "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
                ],
                id='created_min 2',
            ),
            pytest.param(
                dict(created_max="2020-01-01"),
                [],
                id='created_max 0',
            ),
            pytest.param(
                dict(created_max="2025-04-01"),
                [
                    "report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                    "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
                ],
                id='created_max 1',
            ),
            pytest.param(
                dict(created_max="2025-01-01T13:45:58.354498Z"),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='created_max 2',
            ),

            pytest.param(
                dict(description="contains pypotr"),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='description match case',
            ),
            pytest.param(
                dict(description="ConTAiNs pYpOtr"),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='description bad case',
            ),
            pytest.param(
                dict(description="contains pypotr".upper()),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='description upper case',
            ),
            pytest.param(
                dict(name="python vulnerability"),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='name match case',
            ),
            pytest.param(
                dict(name="pYThoN vuLNER"),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='name bad case',
            ),
            pytest.param(
                dict(name="python vulnerability".upper()),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='name upper case',
            ),
            pytest.param(
                dict(tlp_level="amber"),
                [
                    "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
                ],
                id='test tlp_level 0',
            ),
            pytest.param(
                dict(tlp_level="green"),
                [
                    "report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='test tlp_level 1',
            ),

            pytest.param(
                dict(tlp_level="green", name='python'),
                [
                    "report--bc14a07a-5189-5f64-85c3-33161b923627",
                ],
                id='test tlp_level+name',
            ),
        ],
    )
    def test_get_reports(self, client: django.test.Client, filters, expected_ids):
        expected_ids_set = set(expected_ids)
        response = client.get(self.url, query_params=filters)
        assert response.status_code == status.HTTP_200_OK
        assert {obj["id"] for obj in response.data["objects"]} == expected_ids_set


    @pytest.mark.parametrize(
            ['report_id', 'expected_ids'],
            [
                *[(bundle['id'].replace('bundle', 'report'), [obj['id'] for obj in bundle['objects']]) for bundle in [test_data.BUNDLE_1, test_data.BUNDLE_2, test_data.BUNDLE_3]]
            ]
    )
    def test_get_report_objects(self, client, report_id, expected_ids, subtests):
        expected_ids_set = set(expected_ids)
        response = client.get(f"{self.url}{report_id}/objects/")
        assert response.status_code == status.HTTP_200_OK
        objects = response.data["objects"]
        assert {obj["id"] for obj in objects}.issuperset(expected_ids_set), response.data
        for obj in objects:
            if obj['id'] in expected_ids_set:
                continue
            with subtests.test('unexpected id', stix_id=obj['id']):
                assert obj['type'] == 'relationship', 'all unexpected ids must be of type relationship'
                assert obj['source_ref'] in expected_ids_set or obj['target_ref'] in expected_ids_set, 'all unexpected ids must be related to one of expected ids'
    @pytest.mark.parametrize(
            'sort_filter',
            reports.ReportView.SORT_PROPERTIES+[None]
    )
    def test_list_reports_sort(self, client, sort_filter: str):
        DEFAULT = 'modified_descending'
        expected_sort = sort_filter or DEFAULT
        filters = dict(sort=sort_filter) if sort_filter else None
        response = client.get(self.url, query_params=filters)
        assert response.status_code == status.HTTP_200_OK
        report_objects = response.data["objects"]
        assert {obj["type"] for obj in report_objects} == set(["report"]), "expected all returned objects to have type = 'report'"
        property, _, direction = expected_sort.rpartition('_')
        def sort_fn(obj):
            retval = obj[property]
            if property == 'name':
                retval = retval.lower()
            return retval
        assert is_sorted(report_objects, key=sort_fn, reverse=direction == 'descending'), f"expected reports to be sorted by {property} in {direction} order"
