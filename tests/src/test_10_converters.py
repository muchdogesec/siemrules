# test_convert_rule_view.py

import json
from unittest.mock import patch
import pytest
import textwrap
from django.test import RequestFactory
from rest_framework.exceptions import ValidationError
from django.http import HttpResponse
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaTransformationError
from rest_framework.request import Request

from siemrules.siemrules.arangodb_helpers import get_single_rule
from siemrules.siemrules.converters import ConvertRuleView, SplunkBackend, splunk_formats
from sigma.backends.kusto.kusto import KustoBackend
from sigma.backends.elasticsearch import ElastalertBackend



def test_get_pipeline__invalid(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/?pipeline=not_exists"))
    with pytest.raises(ValidationError):
        view.get_pipeline({"a": lambda: None})


def test_get_pipeline__valid(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/?pipeline=exists"))
    view.get_pipeline({"exists": lambda: "the_pipeline_output"}) == "the_pipeline_output"


def test_get_elastic_backend__valid(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/?backend=elastalert"))
    assert view.get_elastic_backend() == ElastalertBackend

def test_get_elastic_backend__missing(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/"))
    with pytest.raises(ValidationError):
        view.get_elastic_backend()

def test_get_elastic_backend_invalid(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/?backend=unknown"))
    with pytest.raises(ValidationError):
        view.get_elastic_backend()

def test_get_splunk_output_format__invalid(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/?output_format=xyz"))
    with pytest.raises(ValidationError):
        view.get_splunk_output_format()


def test_get_splunk_output_format__empty(rf):
    view = ConvertRuleView()
    view.request = Request(rf.get("/"))
    assert view.get_splunk_output_format() == "default"

@pytest.mark.parametrize(
    "format",
    [
        "savedsearches",
        "default",
    ]
)
def test_get_splunk_output_format__valid(rf, format):
    view = ConvertRuleView()
    view.request = Request(rf.get(f"/?output_format={format}"))
    assert view.get_splunk_output_format() == format

def test_convert__transformation_error(rf):
    # force transformation error
    view = ConvertRuleView.as_view({"get": "convert_kusto"})

    with patch.object(KustoBackend, "convert_rule") as mock_convert_rule:
        mock_convert_rule.side_effect = SigmaTransformationError("fail")
        req = rf.get("/?pipeline=azure_monitor")
        resp = view(req, indicator_id="indicator--8af82832-2abd-5765-903c-01d414dae1e9")
        assert resp.status_code == 400
        assert "fail" in json.loads(resp.content)["details"]['error']

@pytest.mark.parametrize(
    ["path", "backend", "pipeline"],
    [
        ("kusto", "", ""),
        ("splunk", "", ""),
        ("elasticsearch", "esql", ""),
        ("elasticsearch", "eql", ""),
        ("elasticsearch", "elastalert", ""),
        ("elasticsearch", "lucene", ""),
    ]
)
def test_convert(client, path, backend, pipeline):
    indicator_id = "indicator--8af82832-2abd-5765-903c-01d414dae1e9"
    
    resp = client.get(f"/api/v1/base-rules/{indicator_id}/convert/{path}/", query_params=dict(backend=backend, pipeline=pipeline))
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "format",
    splunk_formats
)
def test_splunk_output_format(client, format):
    with patch.object(SplunkBackend, 'convert_rule') as mock_convert_rule:
        mock_convert_rule.return_value = ["converted-rule"]
        indicator_id = "indicator--8af82832-2abd-5765-903c-01d414dae1e9"
    
        resp = client.get(f"/api/v1/base-rules/{indicator_id}/convert/splunk/", query_params=dict(output_format=format))
        assert resp.status_code == 200
        mock_convert_rule.assert_called_once()
        mock_convert_rule.call_args[1] == dict(output_format=format)