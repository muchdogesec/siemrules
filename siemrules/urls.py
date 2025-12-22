"""
URL configuration for siemrules project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework import routers

from siemrules.siemrules import converters
from siemrules.siemrules.identities import IdentityView
from .siemrules import views, reports
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from dogesec_commons.objects import views as arango_views


from django.http import JsonResponse
def handler404(*args, **kwargs):
    return JsonResponse(dict(code=404, message='non-existent page'), status=404)

def handler500(*args, **kwargs):
    return JsonResponse(dict(code=500, message='internal server error'), status=500)


router = routers.SimpleRouter()
router.register('files', views.FileView, 'files')
router.register('jobs', views.JobView, 'jobs')
router.register('correlation-rules', views.CorrelationRuleView, 'correlation-rules')
router.register('base-rules', views.BaseRuleView, 'base-rules')
router.register('base-rules', converters.ConvertRuleView, 'convert-base-rules')
router.register('reports', reports.ReportView, 'reports')
router.register('identities', IdentityView, "identity-view")
router.register('profiles', views.ProfileView, "profile-view")
router.register('data-sources', views.DataSourceView, 'data-sources')


# objects
router.register('objects/smos', arango_views.SMOView, "object-view-smo")
router.register('objects/scos', arango_views.SCOView, "object-view-sco")
router.register('objects/sros', arango_views.SROView, "object-view-sro")
router.register('objects/sdos', arango_views.SDOView, "object-view-sdo")
router.register("objects", arango_views.ObjectsWithReportsView, "object-view-orig")

healthcheck = routers.SimpleRouter(use_regex_path=False)
healthcheck.register('', views.HealthCheckView, "service-status-view")

urlpatterns = [
    path(f'api/healthcheck/', include(healthcheck.urls)),
    path('admin/', admin.site.urls),
    path('api/v1/', include(router.urls))
]


urlpatterns += [
    path('api/schema/', views.SchemaViewCached.as_view(), name='schema'),
    # Optional UI:
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]