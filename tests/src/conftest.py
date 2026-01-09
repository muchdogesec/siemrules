import uuid
import pytest


from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules.models import Job, File, Profile


@pytest.fixture
def celery_eager():
    from siemrules.worker.celery import app

    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False


@pytest.fixture
def job(profile):
    file = File.objects.create(
        id="f4b9c920-33de-4d52-827f-40362f161aca",
        name="test.txt",
        file=SimpleUploadedFile(
            "test.txt", b"dummy content", content_type="text/plain"
        ),
        profile=profile,
        identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
    )
    return Job.objects.create(file=file)

@pytest.fixture
def profile():
    return Profile.objects.create(
        id=uuid.UUID('08de23ca-9d66-4bef-b62b-382d577da2ef'),
        name='test-profile',
    )

@pytest.fixture(scope="session")
def api_schema():
    import schemathesis
    from siemrules.asgi import application

    yield schemathesis.openapi.from_asgi("/api/schema/?format=json", application)


@pytest.fixture
def identities():
    from dogesec_commons.identity.models import Identity

    id1, _ = Identity.objects.get_or_create(
        id="identity--b1ae1a15-abcd-431e-b990-1b9678f35e15",
        defaults={
            'stix': {
                'name': 'Test Identity',
                'identity_class': 'organization',
            }
        }
    )
    id2, _ = Identity.objects.get_or_create(
        id="identity--7b7c3431-429b-45c2-b4e8-9ceb8d2678a9",
        defaults={
            'stix': {
                'name': 'Test Identity 2',
                'identity_class': 'organization',
            }
        }
    )
    return [id1, id2]