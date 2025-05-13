import io
import textwrap
from django.core.files.uploadedfile import InMemoryUploadedFile, SimpleUploadedFile
from rest_framework import serializers, validators
import txt2detection
import txt2detection.models
import txt2detection.utils
import txt2detection.utils
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
class STIXIdentityField(serializers.DictField):
    pass

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
    created = serializers.DateTimeField(default=None, help_text="By default the `data` and `modified` values in the rule will be used. If no values exist for these, the default behaviour is to use script run time. You can pass  `created` time here which will overwrite `date` and `modified` date in the rule")
    identity = STIXIdentityField(write_only=True, required=False, help_text='This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the Stixify identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/stixify.json). This is a txt2detection setting.')
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.RED.value, help_text='This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting. Default is `tlp.clear`')
    labels = serializers.ListField(child=serializers.CharField(), required=False, help_text="Will be added to the `labels` of the Report and Indicator SDOs created, and `tags` in the Sigma rule itself. Must pass in format `namespace.value`. This is a txt2detection setting. Note: you cannot use the reserved `tlp.` namespace. Use the `tlp_level` setting to set this. Note: you cannot use reserved namespaces `cve.` and `attack.`. The AI will add these based on the rule content.")
    references = serializers.ListField(child=serializers.URLField(), default=list, help_text="A list of URLs to be added as `references` in the Sigma Rule property and in the `external_references` property of the Indicator and Report STIX object created (e.g. `https://www.dogesec.com`). This is a txt2detection setting.")
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

class FileSigmaSerializer(serializers.ModelSerializer):
    type_label = 'siemrules.sigma'
    mode = serializers.HiddenField(default="sigma")
    ai_provider = serializers.HiddenField(default=None)
    sigma_file = serializers.FileField(source='file', write_only=True, help_text="A Sigma Base Rule. Must be in `.yaml` of `yml` format and conform to the [Sigma Rule specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md). If the Base Rule contains an `id` this will be overwritten with a new ID to avoid conflicts. The old `id` will be captured in the `related` part of the rule. You cannot upload Sigma Correlation Rules using this endpoint.")
    report_id = ReportIDField(source='id', help_text="Pass a full STIX Report ID in the format `report--<UUID>` (e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`. It will be use to generate the STIX Report ID generated to capture the file uploaded (the Indicator ID for the Rule will be different). If not passed, this value will be randomly generated for this file. Must be unique. This is a txt2detection setting.", validators=[
        validators.UniqueValidator(queryset=File.objects.all(), message="File with report id already exists"),
    ], required=False)
    name = serializers.CharField(help_text='Will be assigned as `title` of the rule. Will overwrite any existing `title` in the Sigma Base Rule. Will also be assigned to the STIX Report object created.', required=False)
    created = serializers.DateTimeField(default=None, help_text="By default the `date` and `modified` values in the rule will be used to create STIX `created` and `modified` times. If no values exist in the Rule for these properties, the default behaviour is to use script run time. You can pass  `created` time here which will overwrite `date` and `modified` date in the rule with the value entered. Pass the value in the format `YYYY-MM-DDTHH:MM:SS`")
    identity = STIXIdentityField(write_only=True, required=False, help_text="A full STIX 2.1 identity object (make sure to properly escape). e.g. `{\"type\":\"identity\",\"spec_version\":\"2.1\",\"id\":\"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15\",\"name\":\"Dummy Identity\"}` Will be validated by the STIX2 library. The ID is used to create the Indicator and Report STIX objects, and is used as the `author` property in the Sigma Rule. Will overwrite any existing `author` value. If `author` value in rule, will be converted into a STIX Identity")
    labels = serializers.ListField(child=serializers.CharField(), required=False, help_text=textwrap.dedent("""
    Case-insensitive (will all be converted to lower-case). Allowed `a-z`, `0-9`. e.g.`"namespace.label1" "namespace.label2"` would create 2 labels. Added to both report and indicator objects created and the rule `tags`. Note, if any existing `tags` in the rule, these values will be appended to the list.
    * note: you can use reserved namespaces `cve.` and `attack.` when creating labels to perform external enrichment using Vulmatch and CTI Butler. Created tags will be appended to the list of existing tags.
    * note: you cannot use the namespace `tlp.` You can define this using the `tlp_level` setting.
    """))
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.RED.value, help_text='If TLP exist in rule tags (e.g. `tlp.red`), setting a value for this property will overwrite the existing value. When unset, the `tlp.` tag in the report will be turned into a TLP level for the STIX objects created. Defaults to `clear` if there is no `tlp.` tag in rule and none passed in the request.')
    references = serializers.ListField(child=serializers.URLField(), default=list, help_text='A list of URLs to be added as `references` in the Sigma Rule property and in the `external_references` property of the Indicator and Report STIX object created. e.g `"https://www.google.com/"`, `"https://www.facebook.com/"`. Will appended to any existing `references` in the rule.')
    license = serializers.ChoiceField(default=None, choices=list(valid_licenses().items()), allow_null=True, help_text="[License of the rule according the SPDX ID specification](https://spdx.org/licenses/). Will be added to the rule as `license`. Will overwrite any existing `license` value in rule.")
    status = serializers.ChoiceField(required=False, choices=[(tag.name, tag.value) for tag in txt2detection.models.Statuses], help_text="If passed, will overwrite any existing `status` recorded in the rule")
    level  = serializers.ChoiceField(required=False, choices=[(level.name, level.value) for level in txt2detection.models.Level], help_text="If passed, will overwrite any existing `level` recorded in the rule")
    ignore_embedded_relationships = serializers.BooleanField(default=False, help_text="Default is `false`. Setting this to `true` will stop stix2arango creating relationship objects for the embedded relationships found in objects created by txt2detection. If you want to target certain object types see `ignore_embedded_relationships_sro` and `ignore_embedded_relationships_sro` flags. This is a stix2arango setting.")
    ignore_embedded_relationships_sro = serializers.BooleanField(default=False, help_text="Default is `false`. If `true` passed, will stop any embedded relationships from being generated from SRO objects (type = `relationship`). This is a stix2arango setting.")
    ignore_embedded_relationships_smo = serializers.BooleanField(default=False, help_text="Default is `false`. if true passed, will stop any embedded relationships from being generated from SMO objects (type = `marking-definition`, `extension-definition`, `language-content`). This is a stix2arango setting.")
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
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=None, help_text='This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting. Default is `tlp.clear`')
    title = serializers.CharField(default='Sigma Rule')
    description = serializers.CharField(default='Description for Sigma Rule')