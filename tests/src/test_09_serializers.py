import pytest
from siemrules.siemrules.correlations.utils import validate_author
from siemrules.siemrules.serializers import validate_label, validators, validate_model, ReportIDField
from unittest.mock import patch


def test_validate_model():
    model_name = 'some-model'
    with patch('siemrules.siemrules.serializers.parse_ai_model') as mock_parse_ai_model:
        r = validate_model(model_name)
        mock_parse_ai_model.assert_called_once_with(model_name)
        assert r == model_name

        mock_parse_ai_model.reset_mock()
        mock_parse_ai_model.side_effect = ValueError
        with pytest.raises(validators.ValidationError):
            r = validate_model(model_name)
            mock_parse_ai_model.assert_called_once_with(model_name)

@pytest.mark.parametrize(
    ["report_id", "file_uuid"],
    [
        ["report--29758e19-e9f8-4670-a66f-918a428fb60b", "29758e19-e9f8-4670-a66f-918a428fb60b"],
    ]
)
def test_report_id_field(report_id, file_uuid):
    ReportIDField().to_internal_value(report_id) == file_uuid


@pytest.mark.parametrize(
    "report_id",
        ["repor--29758e19-e9f8-4670-a66f-918a428fb60b", "29758e19-e9f8-4670-a66f-918a428fb60b", "report--4670-a66f-918a428fb60b"],
)
def test_report_id_field_fails(report_id):
    with pytest.raises(validators.ValidationError):
        ReportIDField().to_internal_value(report_id)


@pytest.mark.parametrize("label", [
    "custom.tag",
    "company.product",
    "x-namespace.value123"
])
def test_validate_label_valid(label):
    assert validate_label(label) == label.lower()


@pytest.mark.parametrize("label", [
    "notags",              # No dot
    ".invalid",            # Starts with dot
    "invalid.",            # Ends with dot
    "in valid.tag",        # Space
    "!!!.tag",             # Invalid characters
])
def test_validate_label_invalid_format(label):
    with pytest.raises(validators.ValidationError, match="Invalid label"):
        validate_label(label)


@pytest.mark.parametrize("label", [
    "tlp.red",
    "attack.t1234",
    "cve.2023-12345"
])
def test_validate_label_unsupported_namespace(label):
    with pytest.raises(validators.ValidationError, match="unsupported namespace"):
        validate_label(label)

@pytest.mark.django_db
@pytest.mark.parametrize("author", [
    "identity--not-a-uuid",
    "identity--2573cdbc-3db3-463f-a10f-7fbd8ee17ec8", # UUID does not exist in the test DB
])
def test_validate_author_bad(author):
    with pytest.raises(ValueError):
        validate_author(author)

@pytest.mark.django_db
@pytest.mark.parametrize("author", [
    "identity--7b7c3431-429b-45c2-b4e8-9ceb8d2678a9", # UUID exists in the test DB
    "identity--b1ae1a15-abcd-431e-b990-1b9678f35e15",
])
def test_validate_author_good(author, identities):
    r = validate_author(author)
    assert r == author

@pytest.mark.parametrize("name,expected_id", [
    ("My test identity", "identity--86450c4b-5eff-507e-863c-6643168c0cd9"),
    ("Report identity", "identity--14ed3fa9-f821-52b1-9df6-a2e413bd8e98"),
]
)
def test_validate_author_creates_valid_id(name, expected_id, client):
    author = validate_author(name)
    assert author == expected_id
    resp = client.get(f'/api/v1/identities/{expected_id}/')
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "type": "identity",
        "spec_version": "2.1",
        "id": expected_id,
        "created_by_ref": "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": name,
    }
