import json
import random
import time
from unittest.mock import patch
from urllib.parse import urlencode
import uuid
import schemathesis
import pytest
from schemathesis.core.transport import Response as SchemathesisResponse
from siemrules.siemrules.models import File, Job
from siemrules.wsgi import application as wsgi_app
from rest_framework.response import Response as DRFResponse
from hypothesis import given, settings
from hypothesis import strategies
from schemathesis.specs.openapi.checks import (
    negative_data_rejection,
    positive_data_acceptance,
    status_code_conformance
)
from schemathesis.config import GenerationConfig
from schemathesis.transport.serialization import (
    serialize_binary,
    serialize_json,
    serialize_xml,
    serialize_yaml,
)

schema = schemathesis.openapi.from_wsgi("/api/schema/?format=json", wsgi_app)
schema.config.base_url = "http://localhost:8008/"
schema.config.generation = GenerationConfig(allow_x00=False)


@pytest.fixture(autouse=True)
def override_transport(monkeypatch):
    ## patch transport.get
    from schemathesis import transport
    from ..utils import Transport
    monkeypatch.setattr(transport, "get", lambda _: Transport())


@pytest.fixture(autouse=True)
def module_setup(db):
    file = File.objects.create(
        name="test.txt",
        file=None,
        id="65c0335f-9dff-4885-b0fc-62152fe1666b",
        mode="txt",
    )
    file2 = File.objects.create(
        name="test.txt", file=None, id="6b74370b-7cb8-4db7-a687-d8ad82c9c004", mode="md"
    )
    file3 = File.objects.create(
        name="test.txt",
        file=None,
        id="c92f9e37-0402-4d2d-a388-2424606d3c44",
        mode="pdf",
    )
    Job.objects.create(file=file, id="6b74370b-7cb8-4db7-a687-d8ad82c9c004")
    Job.objects.create(file=file2, id="6aabb7f4-4a9d-45d7-a013-0848a0e14ca9")
    Job.objects.create(file=file3, id="04dc2a6b-468f-4b15-8e17-3af360a6133c")
    yield


file_job_ids = strategies.sampled_from(
    [uuid.uuid4() for _ in range(3)]
    + [
        "65c0335f-9dff-4885-b0fc-62152fe1666b",
        "6b74370b-7cb8-4db7-a687-d8ad82c9c004",
        "c92f9e37-0402-4d2d-a388-2424606d3c44",
        "6aabb7f4-4a9d-45d7-a013-0848a0e14ca9",
        "04dc2a6b-468f-4b15-8e17-3af360a6133c",
    ]
)
object_id_samples = [
    "indicator--0e95725d-7320-415d-80f7-004da920fc11",
    "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72",
    "indicator--8072047b-998e-43fc-a807-15c669c7343b",
    "indicator--8af82832-2abd-5765-903c-01d414dae1e9",
    "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",
    "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
    "report--8af82832-2abd-5765-903c-01d414dae1e9",
    "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
    "vulnerability--a99faefb-377e-585b-9890-70f73d75ffee",
    "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
    "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
    "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
    "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
    "relationship--3c7d73b5-235f-5e62-84ae-9f0ed73eaaa4",
    "relationship--5fc94cc8-425c-539c-8b4c-e54e1e722a3f",
    "relationship--96117a14-7624-562c-84a2-8ec99e2a6481",
    "relationship--9bdf5cb0-9fd1-518d-92d2-0bc64bf6907f",
    "relationship--cc49ffa3-34d1-5136-bbc9-f85a94137d7e",
    "relationship--e8cafeee-8786-5960-9dcc-667fdaeb0a9e",
    "relationship--f5e45557-ced2-5ec6-9af1-699163f5b9a9",
    "relationship--fd32d711-a8f0-5f42-9856-79ecf345c451",
]
indicator_ids = ["indicator--" + str(uuid.uuid4()) for _ in range(3)] + [x for x in object_id_samples if x.startswith("indicator--")]

object_ids = strategies.sampled_from(object_id_samples)
report_ids = strategies.sampled_from(
    ["report--" + str(uuid.uuid4()) for _ in range(3)]
    + [
        "report--2683daab-aa64-52ff-a001-3ea5aee9dd72",
        "report--8af82832-2abd-5765-903c-01d414dae1e9",
        "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
    ]
)


@schema.given(
        indicator_id=strategies.sampled_from(indicator_ids),
)
@schema.include(path_regex=".*/convert/.*").parametrize()
@settings(max_examples=30)
def test_convert(case: schemathesis.Case, indicator_id):
    if 'indicator_id' in case.path_parameters:
        case.path_parameters['indicator_id'] = indicator_id
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance, status_code_conformance]
    )

@schema.include(method=["POST", "PATCH"]).parametrize()
@patch("celery.app.task.Task.run")
def test_imports(mock, case: schemathesis.Case, **kwargs):
    if "indicator_id" in case.path_parameters:
        case.path_parameters["indicator_id"] = random.choice(
            [x for x in object_id_samples if x.startswith("indicator--")]
        )
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance]
    )


@schema.given(
        report_id=report_ids,
        indicator_id=strategies.sampled_from(indicator_ids),
        object_id=object_ids
)
@schema.exclude(method=["POST", "PATCH"]).exclude(path_regex=".*/convert/.*").parametrize()
@settings(max_examples=30)
def test_api(case: schemathesis.Case, **kwargs):
    for k, v in kwargs.items():
        if k in case.path_parameters:
            case.path_parameters[k] = v
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance]
    )


@schemathesis.serializer("application/sigma+yaml")
def serialize_sigma(ctx, value):
    return serialize_yaml(value)
