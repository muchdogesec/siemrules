from rest_framework import viewsets, parsers, decorators, mixins, renderers
from django.db import models
import yaml

from siemrules.siemrules.modifier import yaml_to_detection

class TLP_Levels(models.TextChoices):
    RED = "red"
    AMBER_STRICT = "amber+strict", "AMBER+STRICT"
    AMBER = "amber"
    GREEN = "green"
    CLEAR = "clear"

TLP_LEVEL_STIX_ID_MAPPING = {
    TLP_Levels.RED: "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    TLP_Levels.CLEAR: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    TLP_Levels.GREEN: "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    TLP_Levels.AMBER: "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    TLP_Levels.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
}

class SigmaRuleRenderer(renderers.OpenAPIRenderer):
    format = 'sigma'
    media_type = 'application/sigma+yaml'

    def render(self, data, media_type=None, renderer_context=None):
        return data['pattern'].encode('utf-8')
    
class SigmaRuleParser(parsers.BaseParser):
    format = 'sigma'
    media_type = 'application/sigma+yaml'

    def parse(self, stream, media_type=None, parser_context=None):
        try:
            return yaml.safe_load(stream)
        except:
            raise
