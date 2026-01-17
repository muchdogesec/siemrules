from collections.abc import Mapping
from enum import StrEnum, auto
import uuid
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import serializers, validators
from siemrules.siemrules.models import File, Job, FileImage, Profile, TLP_Levels, Version
from drf_spectacular.utils import extend_schema_field
import file2txt.parsers.core as f2t_core
from txt2detection.utils import parse_model as parse_ai_model, valid_licenses
from django.template.defaultfilters import slugify
import stix2, json
from txt2detection.models import TAG_PATTERN
from dogesec_commons.utils.serializers import JSONSchemaSerializer
from django.utils.translation import gettext_lazy


def validate_ref(value: str):
    if not (value.endswith("_ref") or value.endswith("_refs")):
        raise validators.ValidationError("value must end with _ref or _refs")
    return value


def validate_model(model):
    if not model:
        return None
    try:
        extractor = parse_ai_model(model)
    except BaseException as e:
        raise validators.ValidationError(f"invalid model: {model}")
    return model


def validate_label(label: str):
    label = label.lower()
    if not TAG_PATTERN.match(label):
        raise validators.ValidationError(
            f"Invalid label, must be in format <namespace>.<value> and match pattern {TAG_PATTERN.pattern}"
        )
    namespace, _, _ = label.partition(".")
    if namespace in ["tlp", "attack", "cve"]:
        raise validators.ValidationError(f"unsupported namespace `{namespace}`")
    return label


class StixIdField(serializers.CharField):
    stix_type = None

    def to_internal_value(self, data: str):
        if not isinstance(data, str):
            raise validators.ValidationError("string expected")
        if not data.startswith(self.stix_type + "--"):
            raise validators.ValidationError(
                "invalid STIX Report ID, must be in format `report--{UUID}`"
            )
        _, _, data = data.rpartition("--")
        return serializers.UUIDField().to_internal_value(data)

    def to_representation(self, value):
        if '--' in str(value):
            return value
        return self.stix_type + "--" + serializers.UUIDField().to_representation(value)


@extend_schema_field({"example": "report--3fa85f64-5717-4562-b3fc-2c963f66afa6"})
class ReportIDField(StixIdField):
    stix_type = "report"


@extend_schema_field({"example": "indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6"})
class IndicatorIDField(StixIdField):
    stix_type = "indicator"


class CharacterSeparatedField(serializers.ListField):
    def __init__(self, *args, **kwargs):
        self.separator = kwargs.pop("separator", ",")
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        if isinstance(data, (str, Mapping)) or not hasattr(data, "__iter__"):
            self.fail("not_a_list", input_type=type(data).__name__)
        retval = []
        if hasattr(self.parent, "skip_csv"):
            retval = data
        else:
            for s in data:
                if not isinstance(s, str):
                    retval.append(s)
                    continue
                retval.extend(s.split(self.separator))
        return super().to_internal_value(retval)


class ProfileIDField(serializers.PrimaryKeyRelatedField):
    def __init__(self, **kwargs):
        super().__init__(
            queryset=Profile.objects,
            error_messages={
                "required": gettext_lazy("This field is required."),
                "does_not_exist": gettext_lazy(
                    'Invalid profile with id "{pk_value}" - object does not exist.'
                ),
                "incorrect_type": gettext_lazy(
                    "Incorrect type. Expected profile id (uuid), received {data_type}."
                ),
            },
            **kwargs,
        )

    def to_internal_value(self, data):
        return super().to_internal_value(data).pk

    def to_representation(self, value):
        if isinstance(value, uuid.UUID):
            return value
        return super().to_representation(value)
    
class IdentityIDField(serializers.PrimaryKeyRelatedField):
    def __init__(self, **kwargs):
        from dogesec_commons.identity.models import Identity
        super().__init__(
            queryset=Identity.objects,
            error_messages={
                "required": gettext_lazy("This field is required."),
                "does_not_exist": gettext_lazy(
                    'Invalid identity with id "{pk_value}" - object does not exist.'
                ),
                "incorrect_type": gettext_lazy(
                    "Incorrect type. Expected identity id (uuid), received {data_type}."
                ),
            },
            **kwargs,
        )

    def to_internal_value(self, data):
        return super().to_internal_value(data).pk

    def to_representation(self, value):
        if isinstance(value, str):
            return value
        return super().to_representation(value)


class FileSerializer(serializers.ModelSerializer):
    job_id = serializers.UUIDField(source="job.id", read_only=True)
    mimetype = serializers.CharField(read_only=True)
    download_url = serializers.FileField(source="file", read_only=True, allow_null=True)
    file = serializers.FileField(
        write_only=True,
        help_text="Full path to the file to be converted. The mimetype of the file uploaded must match that expected by the `mode` selected. This is a file2txt setting.",
    )
    mode = serializers.ChoiceField(
        choices=list(["txt", "html", "html_article", "word", "pdf", "md"]),
        help_text="How the File should be processed. This is a file2txt setting.",
    )
    report_id = ReportIDField(
        source="id",
        help_text="If you want to define the UUID of the STIX Report object you can use this property. Pass the entire report id, e.g. `report--26dd4dcb-0ebc-4a71-8d37-ffd88faed163`. The UUID part will also be used for the file ID. If not passed, this UUID will be randomly generated. Must be unique.",
        validators=[
            validators.UniqueValidator(
                queryset=File.objects.all(),
                message="File with report id already exists",
            ),
        ],
        required=False,
    )
    profile_id = ProfileIDField(help_text="profile id to use", required=False, allow_null=True)
    created = serializers.DateTimeField(
        default=None,
        help_text="By default the `data` and `modified` values in the rule will be used. If no values exist for these, the default behaviour is to use script run time. You can pass  `created` time here which will overwrite `date` and `modified` date in the rule. Pass as `YYYY-MM-DDThh:mm:ssZ` (e.g. `2020-01-01T00:00:00`)",
    )
    identity_id = IdentityIDField(
        required=False,
        help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the SIEM Rules identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/siemrules.json). This is a txt2detection setting.',
    )
    tlp_level = serializers.ChoiceField(
        choices=TLP_Levels.choices,
        default=TLP_Levels.CLEAR.value,
        help_text="This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.",
    )
    labels = CharacterSeparatedField(
        child=serializers.CharField(validators=[validate_label]),
        required=False,
        help_text="Will be added to the `labels` of the Report and Indicator SDOs created, and `tags` in the Sigma rule itself. Must pass in format `namespace.value`. This is a txt2detection setting. Note: you cannot use the reserved `tlp.` namespace. Use the `tlp_level` setting to set this. Note: you cannot use reserved namespaces `cve.` and `attack.`. The AI will add these based on the rule content.",
    )
    references = CharacterSeparatedField(
        child=serializers.URLField(),
        default=list,
        help_text="A list of URLs to be added as `references` in the Sigma Rule property and in the `external_references` property of the Indicator and Report STIX object created (e.g. `https://www.dogesec.com`). This is a txt2detection setting.",
    )
    license = serializers.ChoiceField(
        default=None,
        choices=list(valid_licenses().items()),
        allow_null=True,
        help_text="[License of the rule according the SPDX ID specification](https://spdx.org/licenses/) (e.g. `MIT`). Will be added to the Sigma rule. This is a txt2detection setting.",
    )
    archived_pdf = serializers.FileField(
        required=False,
        allow_null=True,
        read_only=True
    )

    class Meta:
        model = File
        exclude = ["markdown_file", "status", "level", "profile", "txt2detection_data", "pdf_file", "identity"]
        read_only_fields = ["id", "type"]

    def validate(self, attrs):
        attrs['identity_id'] = attrs.get('identity_id', settings.STIX_IDENTITY['id'])
        return super().validate(attrs)


class ProfileSerializer(serializers.ModelSerializer):
    ai_provider = serializers.CharField(
        required=True,
        validators=[validate_model],
        help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`.",
    )

    ignore_embedded_relationships = serializers.BooleanField(
        required=False, help_text="applies to SDO and SCO types (default is `false`)"
    )
    ignore_embedded_relationships_sro = serializers.BooleanField(
        required=False,
        help_text="sets wether to ignore embedded refs on `relationship` object types (default is `true`)",
    )
    ignore_embedded_relationships_smo = serializers.BooleanField(
        required=False,
        help_text="sets wether to ignore embedded refs on SMO object types (`marking-definition`, `extension-definition`, `language-content`) (default is `true`)",
    )
    include_embedded_relationships_attributes = serializers.ListField(
        required=False,
        child=serializers.CharField(
            max_length=128,
            validators=[validate_ref],
        ),
        help_text="Only create embedded relationships for STIX attributes that match items in this list",
    )
    generate_pdf = serializers.BooleanField(
        required=False,
        help_text="Whether or not to generate pdf file for input, applies to both stixify and obstracts (default is `false`)",
    )

    class Meta:
        model = Profile
        fields = "__all__"
        read_only_fields = ["id", "created", "is_default"]


class FileDocumentSerializer(FileSerializer):
    type_label = "siemrules.file"
    profile_id = ProfileIDField(help_text="profile id to use", required=True, allow_null=False)


class FilePromptSerializer(FileDocumentSerializer):
    type_label = "siemrules.text"

    file = serializers.HiddenField(default="")
    text_input = serializers.CharField(write_only=True)
    mode = serializers.HiddenField(default="txt")
    # extract_text_from_image = serializers.HiddenField(default=False)

    def create(self, validated_data):
        validated_data["file"] = SimpleUploadedFile(
            "text-input--" + slugify(validated_data["name"]) + ".txt",
            validated_data.pop("text_input", "").encode(),
            "text/plain",
        )
        return super().create(validated_data)


class FileSigmaYamlSerializer(serializers.ModelSerializer):
    type_label = "siemrules.sigma"
    mode = serializers.HiddenField(default="sigma")
    # ai_provider = serializers.HiddenField(default=None)
    tlp_level = serializers.CharField(required=True)
    sigma_file = serializers.FileField(source="file", write_only=True)
    name = serializers.CharField(required=False)
    created = serializers.DateTimeField(default=None)
    identity_id = IdentityIDField(write_only=True, required=True)

    class Meta:
        model = File
        exclude = [
            "file",
            "markdown_file",
            "mimetype",
            "identity",
        ]
        read_only_fields = ["id"]


class ImageSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = FileImage
        fields = ["name", "url"]

    @extend_schema_field(serializers.CharField())
    def get_url(self, instance: FileImage):
        request = self.context.get("request")
        if instance.image and hasattr(instance.image, "url"):
            photo_url = instance.image.url
            return request.build_absolute_uri(photo_url)
        return None

class CorrelationJobSerializer(serializers.ModelSerializer):
    correlation_id = IndicatorIDField(source="data.correlation_id")
    extra = serializers.DictField(source="data", required=False, allow_null=True)

    class Meta:
        model = Job
        exclude = ["data", "file"]


class JobSerializer(CorrelationJobSerializer):
    correlation_id = None
    report_id = ReportIDField(source="file_id", required=False, allow_null=True)
    file_id = serializers.UUIDField(required=False, allow_null=True)
    profile_id = serializers.UUIDField(source='file.profile_id', required=False, allow_null=True)


class RuleSerializer(serializers.Serializer):
    id = serializers.CharField(
        default="indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6"
    )
    pattern_type = serializers.CharField(default="sigma")
    type = serializers.ChoiceField(choices=[("indicator", "SIEM Rule")])


class RuleSigmaSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    name = serializers.CharField(default="Sigma Rule")
    description = serializers.CharField(default="Description for Sigma Rule")


class AIModifySerializer(serializers.Serializer):
    prompt = serializers.CharField(help_text="prompt to send to the AI processor")
    ai_provider = serializers.CharField(
        required=True,
        validators=[validate_model],
        help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.",
    )


class RuleRevertSerializer(serializers.Serializer):
    version = serializers.DateTimeField()


class RuleCloneSerializer(serializers.Serializer):
    identity_id = IdentityIDField(
        write_only=True,
        default=settings.STIX_IDENTITY['id'],
        help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the Stixify identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/stixify.json). This is a txt2detection setting.',
    )
    tlp_level = serializers.ChoiceField(
        choices=TLP_Levels.choices,
        default=None,
        help_text="This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.",
    )
    title = serializers.CharField(required=False)
    description = serializers.CharField(required=False)


class HealthCheckChoices(StrEnum):
    AUTHORIZED = auto()
    UNAUTHORIZED = auto()
    UNSUPPORTED = auto()
    NOT_CONFIGURED = "not-configured"
    UNKNOWN = auto()
    OFFLINE = auto()


class HealthCheckChoiceField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        choices = [m.value for m in HealthCheckChoices]
        super().__init__(choices, **kwargs)


class HealthCheckLLMs(serializers.Serializer):
    openai = HealthCheckChoiceField()
    deepseek = HealthCheckChoiceField()
    anthropic = HealthCheckChoiceField()
    gemini = HealthCheckChoiceField()
    openrouter = HealthCheckChoiceField()


class HealthCheckSerializer(serializers.Serializer):
    ctibutler = HealthCheckChoiceField()
    vulmatch = HealthCheckChoiceField()
    llms = HealthCheckLLMs()


class AttackNavigatorDomainSerializer(JSONSchemaSerializer):
    json_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "MITRE ATT&CK Navigator Layer v4.5",
        "type": "object",
        "required": ["versions", "name", "domain", "techniques"],
        "properties": {
            "versions": {
                "type": "object",
                "properties": {
                    "layer": {"type": "string", "example": "4.5"},
                    "attack": {"type": "string", "example": "17.0"},
                    "navigator": {"type": "string", "example": "5.1.0"},
                },
                "required": [
                    "layer",
                    # "attack",
                    "navigator",
                ],
                "additionalProperties": False,
            },
            "name": {"type": "string"},
            "domain": {
                "type": "string",
                "enum": ["enterprise-attack", "mobile-attack", "ics-attack"],
            },
            "description": {"type": "string"},
            "gradient": {
                "type": "object",
                "required": ["colors", "minValue", "maxValue"],
                "properties": {
                    "colors": {
                        "type": "array",
                        "items": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                    },
                    "minValue": {"type": "number"},
                    "maxValue": {"type": "number"},
                },
            },
            "legendItems": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                        "value": {"type": "number"},
                    },
                },
            },
            "showTacticsRowBackground": {"type": "boolean"},
            "techniques": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["techniqueID"],
                    "properties": {
                        "techniqueID": {"type": "string"},
                        "tactic": {"type": "string"},
                        "score": {"type": ["number", "null"]},
                        "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                        "comment": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "links": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "href": {"type": "string", "format": "uri"},
                                    "text": {"type": "string"},
                                },
                                "required": ["href", "text"],
                            },
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "tacticUseIds": {"type": "array", "items": {"type": "string"}},
            "filters": {
                "type": "object",
                "properties": {
                    "includeSubtechniques": {"type": "boolean"},
                    "showOnlyVisibleTechniques": {"type": "boolean"},
                },
            },
        },
        "additionalProperties": True,
    }


class VersionSerializer(serializers.ModelSerializer):
    file_id = serializers.UUIDField(source='real_file_id', read_only=True, required=False)
    class Meta:
        model = Version
        exclude = ['id', 'rule_id', 'rule_type', "job", "file"]
