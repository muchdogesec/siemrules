import django
import pytest


import django.test
from rest_framework import status
from unittest.mock import patch
from siemrules.siemrules import reports
from rest_framework.response import Response
from rest_framework.validators import ValidationError

from tests.src.utils import is_sorted


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

    @pytest.mark.parametrize(
        ["filters", "expected_ids"],
        [
            pytest.param(
                dict(),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                    "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                ],
                id="no filter",
            ),
            pytest.param(dict(created_min="2050-01-01"), []),
            pytest.param(
                dict(created_min="2001-01-01"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                    "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                ],
                id="created_min 1",
            ),
            pytest.param(
                dict(created_max="2020-01-01"),
                [],
                id="created_max 0",
            ),
            pytest.param(
                dict(description="modifies the liblzma"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="description match case",
            ),
            pytest.param(
                dict(description="modifies the liblzma".upper()),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="description upper case",
            ),
            pytest.param(
                dict(name="Malicious Code"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="name match case",
            ),
            pytest.param(
                dict(name="maliciOuS cOde"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="name bad case",
            ),
            pytest.param(
                dict(tlp_level="amber"),
                [
                    "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                ],
                id="test tlp_level 0",
            ),
            pytest.param(
                dict(tlp_level="red"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="test tlp_level 1",
            ),
            pytest.param(
                dict(tlp_level="green"),
                [
                ],
                id="test tlp_level",
            ),
            pytest.param(
                dict(tlp_level="red", name="PyPI Package"),
                [
                ],
                id="test tlp_level+bad_name",
            ),
            pytest.param(
                dict(tlp_level="red", name="malicio"),
                [
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                ],
                id="test tlp_level+good_name",
            ),
            pytest.param(
                dict(indicator_id="indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"),
                ["report--9e2536b0-988b-598d-8cc3-407f9f13fc61"],
                id="indicator_id good",
            ),
            pytest.param(
                dict(indicator_id="indicator--abcdef12-2abd-5765-903c-01d414dae1e9"),
                [],
                id="indicator_id bad",
            ),
        ],
    )
    def test_get_reports(self, client: django.test.Client, filters, expected_ids):
        expected_ids_set = set(expected_ids)
        response = client.get(self.url, query_params=filters)
        assert response.status_code == status.HTTP_200_OK
        print({obj["id"] for obj in response.data["objects"]})
        print(expected_ids_set)
        assert {obj["id"] for obj in response.data["objects"]} == expected_ids_set

    @pytest.mark.parametrize(
        ["report_id", "expected_ids"],
        [

            (
                "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                [
                    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
                    "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
                    "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
                    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                    "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",
                    "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
                    "relationship--9bdf5cb0-9fd1-518d-92d2-0bc64bf6907f",
                    "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                    "relationship--cc49ffa3-34d1-5136-bbc9-f85a94137d7e",
                    "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
                    "relationship--fd32d711-a8f0-5f42-9856-79ecf345c451",
                    "data-source--512ead3c-b0fb-5235-8605-2da7c9b35ac2",
                    "attack-pattern--f24faf46-3b26-4dbb-98f2-63460498e433",
                ],
            ),
            (
                "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                [
                    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                    "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
                    "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
                    "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                    "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72",
                    "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                    "relationship--869b7105-3f66-560b-9dd6-e681765463dc",
                    "vulnerability--916e004a-e101-5b48-91c6-c2b4c4a0942c",
                    "relationship--e8cafeee-8786-5960-9dcc-667fdaeb0a9e",
                    "data-source--ab14f1cd-18db-5805-9c75-8d6002e41d9a",
                    "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69",
                    "attack-pattern--937e4772-8441-4e4a-8bf0-8d447d667e23",
                ],
            ),
        ],
    )
    def test_get_report_objects(self, client, report_id, expected_ids, subtests):
        expected_ids_set = set(expected_ids)
        response = client.get(f"{self.url}{report_id}/objects/")
        assert response.status_code == status.HTTP_200_OK
        objects = response.data["objects"]
        print({obj["id"] for obj in objects if obj.get("type") == "identity"})
        print(expected_ids_set.difference({obj["id"] for obj in objects}))
        print(sorted({obj["id"] for obj in objects}))
        assert {obj["id"] for obj in objects}.issuperset(
            expected_ids_set
        ), response.data
        for obj in objects:
            if obj["id"] in expected_ids_set:
                continue
            with subtests.test("unexpected id", stix_id=obj["id"]):
                if obj["type"] == "extension-definition":
                    continue
                assert (
                    obj["type"] == "relationship"
                ), "all unexpected ids must be of type relationship"
                assert (
                    obj["source_ref"] in expected_ids_set
                    or obj["target_ref"] in expected_ids_set
                    or obj["source_ref"].startswith("extension-definition")
                ), "all unexpected ids must be related to one of expected ids"

    @pytest.mark.parametrize("sort_filter", reports.ReportView.SORT_PROPERTIES + [None])
    def test_list_reports_sort(self, client, sort_filter: str):
        DEFAULT = "created_descending"
        expected_sort = sort_filter or DEFAULT
        filters = dict(sort=sort_filter) if sort_filter else None
        response = client.get(self.url, query_params=filters)
        assert response.status_code == status.HTTP_200_OK
        report_objects = response.data["objects"]
        assert {obj["type"] for obj in report_objects} == set(
            ["report"]
        ), "expected all returned objects to have type = 'report'"
        property, _, direction = expected_sort.rpartition("_")

        def sort_fn(obj):
            retval = obj[property]
            if property == "name":
                retval = retval.lower()
            return retval

        assert is_sorted(
            report_objects, key=sort_fn, reverse=direction == "descending"
        ), f"expected reports to be sorted by {property} in {direction} order"
