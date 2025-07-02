import pytest
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