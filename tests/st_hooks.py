from schemathesis.serializers import YAMLSerializer, register

@register("application/sigma+yaml")
class SigmaYamlSerializer(YAMLSerializer):
    pass