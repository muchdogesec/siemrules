from rest_framework import serializers, validators
from .models import File, Job, FileImage
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from txt2detection.utils import load_detection_languages
import file2txt.parsers.core as f2t_core

DETECTION_LANGUAGES = [(k, v.name) for k, v in load_detection_languages().items()]

class FileSerializer(serializers.ModelSerializer):
    job_id = serializers.UUIDField(source='job.id', read_only=True)
    mimetype = serializers.CharField(read_only=True)
    download_url = serializers.FileField(source='file', read_only=True, allow_null=True)
    file = serializers.FileField(write_only=True)
    detection_language = serializers.ChoiceField(choices=DETECTION_LANGUAGES)
    report_id = serializers.UUIDField(source='id', help_text="Only pass a UUIDv4. It will be use to generate the STIX Report ID, e.g. `report--<UUID>`. If not passed, this file will be randomly generated.", validators=[
        validators.UniqueValidator(queryset=File.objects.all(), message="File with report id already exists"),
    ], required=False)
    mode = serializers.ChoiceField(choices=list(f2t_core.BaseParser.PARSERS.keys()), help_text="How the File should be processed. Generally the mode should match the filetype of file selected. Except for HTML documents where you can use html mode (processes entirety of HTML page) and html_article mode (where only the article on the page will be processed)")
    class Meta:
        model = File
        exclude = ['markdown_file', 'identity']
        read_only_fields = ['id']

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
    report_id = serializers.UUIDField(source='file.id')
    class Meta:
        model = Job
        fields = '__all__'


class RuleSerializer(serializers.Serializer):
    id = serializers.CharField(default="indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6")
    type = serializers.ChoiceField(choices=[("indicator", "SIEM Rule")])