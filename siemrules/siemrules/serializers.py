import io
from django.core.files.uploadedfile import InMemoryUploadedFile, SimpleUploadedFile
from rest_framework import serializers, validators
import txt2detection
from siemrules.siemrules.models import File, Job, FileImage, TLP_Levels
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
import file2txt.parsers.core as f2t_core
from txt2detection.utils import parse_model as parse_ai_model, valid_licenses
from django.template.defaultfilters import slugify


def validate_model(model):
    if not model:
        return None
    try:
        extractor = parse_ai_model(model)
    except BaseException as e:
        raise validators.ValidationError(f"invalid model: {model}")
    return model

@extend_schema_field({
    'example': 'report--3fa85f64-5717-4562-b3fc-2c963f66afa6'
})
class ReportIDField(serializers.CharField):
    def to_internal_value(self, data: str):
        if not isinstance(data, str):
            raise validators.ValidationError("string expected")
        if not data.startswith('report--'):
            raise validators.ValidationError("invalid STIX Report ID, must be in format `report--{UUID}`")
        data = data.replace("report--", "")
        return serializers.UUIDField().to_internal_value(data)
    
    def to_representation(self, value):
        return "report--"+serializers.UUIDField().to_representation(value)
    
@extend_schema_field(dict)
class STIXIdentityField(serializers.JSONField):
    pass

class FileSerializer(serializers.ModelSerializer):
    type_label = 'siemrules.file'

    job_id = serializers.UUIDField(source='job.id', read_only=True)
    mimetype = serializers.CharField(read_only=True)
    download_url = serializers.FileField(source='file', read_only=True, allow_null=True)
    file = serializers.FileField(write_only=True, help_text="Full path to the file to be converted. The mimetype of the file uploaded must match that expected by the `mode` selected. This is a file2txt setting.")
    report_id = ReportIDField(source='id', help_text="Only pass a UUIDv4. It will be use to generate the STIX Report ID, e.g. `report--<UUID>`. If not passed, this value will be randomly generated for this file. This is a txt2detection setting.", validators=[
        validators.UniqueValidator(queryset=File.objects.all(), message="File with report id already exists"),
    ], required=False)
    mode = serializers.ChoiceField(choices=list(f2t_core.BaseParser.PARSERS.keys()), help_text="How the File should be processed. This is a file2txt setting.")
    identity = STIXIdentityField(write_only=True, required=False, help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the Stixify identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/stixify.json). his is a txt2detection setting.')
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.RED, help_text='This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.')
    confidence = serializers.IntegerField(max_value=100, min_value=0, required=False, help_text="Will be added to the `confidence` value of the Report SDO created. A value between 0-100. `0` means confidence unknown. `1` is the lowest confidence score, `100` is the highest confidence score.")
    labels = serializers.ListField(child=serializers.CharField(), required=False, help_text="Will be added to the `labels` of the Report SDO created.")
    defang = serializers.BooleanField(default=True, help_text="whether to defang the observables in the blog. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a file2txt setting.")
    ai_provider = serializers.CharField(required=True, validators=[validate_model], help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.")
    extract_text_from_image = serializers.BooleanField(required=False, default=True, help_text="whether to extract text from file's images. This is a file2txt setting.")
    references = serializers.ListField(child=serializers.URLField(), default=list, help_text="references to include in sigma rule's references")
    license = serializers.ChoiceField(default=None, choices=list(valid_licenses().items()), allow_null=True, help_text='valid SPDX license')


    ignore_embedded_relationships = serializers.BooleanField(default=False, help_text="Default is `false`. Setting this to `true` will stop stix2arango creating relationship objects for the embedded relationships found in objects created by txt2detection.")
    ignore_embedded_relationships_sro = serializers.BooleanField(default=False, help_text="if true passed, will stop any embedded relationships from being generated from SRO objects (type = `relationship`).")
    ignore_embedded_relationships_smo = serializers.BooleanField(default=False, help_text="Default is `false`. if true passed, will stop any embedded relationships from being generated from SMO objects (type = `marking-definition`, `extension-definition`, `language-content`).")

    class Meta:
        model = File
        exclude = ['markdown_file']
        read_only_fields = ['id']

    
    def create(self, validated_data):
        labels = validated_data['labels'] = validated_data.get('labels') or []
        labels.insert(0, self.type_label)
        return super().create(validated_data)


class FilePromptSerializer(FileSerializer):
    type_label = 'siemrules.text'
    
    file = serializers.HiddenField(default='')
    text_input = serializers.CharField(write_only=True)
    mode = serializers.HiddenField(default="txt")
    def create(self, validated_data):
        validated_data['file'] = SimpleUploadedFile("text-input--"+slugify(validated_data['name'])+'.txt', validated_data.pop('text_input', '').encode(), "text/plain")
        return super().create(validated_data)

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
    report_id = ReportIDField(source='file.id')
    class Meta:
        model = Job
        fields = '__all__'


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

