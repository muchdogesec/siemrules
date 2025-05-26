from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import serializers, validators
from siemrules.siemrules.models import File, Job, FileImage, TLP_Levels
from drf_spectacular.utils import extend_schema_field
import file2txt.parsers.core as f2t_core
from txt2detection.utils import parse_model as parse_ai_model, valid_licenses
from django.template.defaultfilters import slugify
import stix2, json
from txt2detection.models import TAG_PATTERN


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
        raise validators.ValidationError(f'Invalid label, must be in format <namespace>.<value> and match pattern {TAG_PATTERN.pattern}')
    namespace, _, _ = label.partition('.')
    if namespace in ['tlp', 'attack', 'cve']:
        raise validators.ValidationError(f'unsupported namespace `{namespace}`')
    return label


class StixIdField(serializers.CharField):
    stix_type = None
    def to_internal_value(self, data: str):
        if not isinstance(data, str):
            raise validators.ValidationError("string expected")
        if not data.startswith(self.stix_type + '--'):
            raise validators.ValidationError("invalid STIX Report ID, must be in format `report--{UUID}`")
        _, _, data = data.rpartition('--')
        return serializers.UUIDField().to_internal_value(data)
    
    def to_representation(self, value):
        return self.stix_type+"--"+serializers.UUIDField().to_representation(value)
    
@extend_schema_field({
    'example': 'report--3fa85f64-5717-4562-b3fc-2c963f66afa6'
})
class ReportIDField(StixIdField):
    stix_type = 'report'

@extend_schema_field({
    'example': 'indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6'
})
class IndicatorIDField(StixIdField):
    stix_type = 'indicator'

@extend_schema_field(dict(
    example={"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}, type='object'
))
class STIXIdentityField(serializers.JSONField):
    def run_validators(self, value):
        try:
            identity = stix2.Identity(**value)
            return json.loads(identity.serialize())
        except Exception as e:
            raise validators.ValidationError(e)
        

class CharacterSeparatedField(serializers.ListField):
    def __init__(self, *args, **kwargs):
        self.separator = kwargs.pop("separator", ",")
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
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


class FileSerializer(serializers.ModelSerializer):
    type_label = 'siemrules.file'

    job_id = serializers.UUIDField(source='job.id', read_only=True)
    mimetype = serializers.CharField(read_only=True)
    download_url = serializers.FileField(source='file', read_only=True, allow_null=True)
    file = serializers.FileField(write_only=True, help_text="Full path to the file to be converted. The mimetype of the file uploaded must match that expected by the `mode` selected. This is a file2txt setting.")
    mode = serializers.ChoiceField(choices=list(f2t_core.BaseParser.PARSERS.keys()), help_text="How the File should be processed. This is a file2txt setting.")
    report_id = ReportIDField(source='id', help_text="If you want to define the UUID of the STIX Report object you can use this property. Pass the entire report id, e.g. `report--26dd4dcb-0ebc-4a71-8d37-ffd88faed163`. The UUID part will also be used for the file ID. If not passed, this UUID will be randomly generated. Must be unique.", validators=[
        validators.UniqueValidator(queryset=File.objects.all(), message="File with report id already exists"),
    ], required=False)
    created = serializers.DateTimeField(default=None, help_text="By default the `data` and `modified` values in the rule will be used. If no values exist for these, the default behaviour is to use script run time. You can pass  `created` time here which will overwrite `date` and `modified` date in the rule. Pass as `YYYY-MM-DDThh:mm:ssZ` (e.g. `2020-01-01T00:00:00`)")
    identity = STIXIdentityField(write_only=True, required=False, help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the SIEM Rules identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/siemrules.json). This is a txt2detection setting.')
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.CLEAR.value, help_text='This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.')
    labels = CharacterSeparatedField(child=serializers.CharField(validators=[validate_label]), required=False, help_text="Will be added to the `labels` of the Report and Indicator SDOs created, and `tags` in the Sigma rule itself. Must pass in format `namespace.value`. This is a txt2detection setting. Note: you cannot use the reserved `tlp.` namespace. Use the `tlp_level` setting to set this. Note: you cannot use reserved namespaces `cve.` and `attack.`. The AI will add these based on the rule content.")
    references = CharacterSeparatedField(child=serializers.URLField(), default=list, help_text="A list of URLs to be added as `references` in the Sigma Rule property and in the `external_references` property of the Indicator and Report STIX object created (e.g. `https://www.dogesec.com`). This is a txt2detection setting.")
    license = serializers.ChoiceField(default=None, choices=list(valid_licenses().items()), allow_null=True, help_text='[License of the rule according the SPDX ID specification](https://spdx.org/licenses/) (e.g. `MIT`). Will be added to the Sigma rule. This is a txt2detection setting.')
    defang = serializers.BooleanField(default=True, help_text="Whether to defang the observables in the text. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a file2txt setting.")
    ai_provider = serializers.CharField(required=True, validators=[validate_model], help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.")
    extract_text_from_image = serializers.BooleanField(required=False, default=True, help_text="Whether to convert the images found in a the file to text. Requires a Google Vision key to be set. This is a file2txt setting")
    ignore_embedded_relationships = serializers.BooleanField(default=False, help_text="Default is `false`. Setting this to `true` will stop stix2arango creating relationship objects for the embedded relationships found in objects created by txt2detection.")
    ignore_embedded_relationships_sro = serializers.BooleanField(default=False, help_text="Default is `false`. If `true` passed, will stop any embedded relationships from being generated from SRO objects (type = `relationship`).")
    ignore_embedded_relationships_smo = serializers.BooleanField(default=False, help_text="Default is `false`. if true passed, will stop any embedded relationships from being generated from SMO objects (type = `marking-definition`, `extension-definition`, `language-content`).")    

    class Meta:
        model = File
        exclude = ['markdown_file', 'status', 'level']
        read_only_fields = ['id']

    def create(self, validated_data):
        return super().create(validated_data)


class FilePromptSerializer(FileSerializer):
    type_label = 'siemrules.text'
    
    file = serializers.HiddenField(default='')
    text_input = serializers.CharField(write_only=True)
    mode = serializers.HiddenField(default="txt")
    extract_text_from_image = serializers.HiddenField(default=False)
    def create(self, validated_data):
        validated_data['file'] = SimpleUploadedFile("text-input--"+slugify(validated_data['name'])+'.txt', validated_data.pop('text_input', '').encode(), "text/plain")
        return super().create(validated_data)

class FileSigmaYamlSerializer(serializers.ModelSerializer):
    type_label = 'siemrules.sigma'
    mode = serializers.HiddenField(default="sigma")
    ai_provider = serializers.HiddenField(default=None)
    tlp_level = serializers.CharField(required=True)
    sigma_file = serializers.FileField(source='file', write_only=True)
    name = serializers.CharField(required=False)
    created = serializers.DateTimeField(default=None)
    identity = STIXIdentityField(write_only=True, required=False)
    class Meta:
        model = File
        exclude = ['file', 'defang', 'extract_text_from_image', 'markdown_file', 'mimetype']
        read_only_fields = ["id"]

class ImageSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()
    class Meta:
        model = FileImage
        fields = ["name", "url"]

    @extend_schema_field(serializers.CharField())
    def get_url(self, instance: FileImage):
        request = self.context.get('request')
        if instance.image and hasattr(instance.image, 'url'):
            photo_url = instance.image.url
            return request.build_absolute_uri(photo_url)
        return None

class JobSerializer(serializers.ModelSerializer):
    report_id = ReportIDField(source='file_id', required=False, allow_null=True)
    file_id = serializers.UUIDField(required=False, allow_null=True)
    class Meta:
        model = Job
        exclude = ['data', 'file']


class CorrelationJobSerializer(serializers.ModelSerializer):
    correlation_id = IndicatorIDField(source='data.correlation_id')
    class Meta:
        model = Job
        exclude = ['file']

class RuleSerializer(serializers.Serializer):
    id = serializers.CharField(default="indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6")
    pattern_type = serializers.CharField(default='sigma')
    type = serializers.ChoiceField(choices=[("indicator", "SIEM Rule")])

class RuleSigmaSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    name = serializers.CharField(default='Sigma Rule')
    description = serializers.CharField(default='Description for Sigma Rule')

class AIModifySerializer(serializers.Serializer):
    prompt = serializers.CharField(help_text='prompt to send to the AI processor')
    ai_provider = serializers.CharField(required=True, validators=[validate_model], help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.")

class RuleRevertSerializer(serializers.Serializer):
    version = serializers.DateTimeField()


class RuleCloneSerializer(serializers.Serializer):
    identity = STIXIdentityField(write_only=True, required=False, help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the Stixify identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/stixify.json). This is a txt2detection setting.')
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=None, help_text='This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.')
    title = serializers.CharField(required=False)
    description = serializers.CharField(required=False)