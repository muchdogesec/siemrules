from rest_framework import viewsets, parsers, decorators, mixins, renderers

class SigmaRuleRenderer(renderers.OpenAPIRenderer):
    format = 'sigma'
    media_type = 'application/sigma+yaml'

    def render(self, data, media_type=None, renderer_context=None):
        return data['pattern'].encode('utf-8')