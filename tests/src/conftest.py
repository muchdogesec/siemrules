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
