
import pytest


from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules.models import Job, File

@pytest.fixture
def celery_eager():
    from siemrules.worker.celery import app
    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False



@pytest.fixture
def job():
    file = File.objects.create(name="test.txt", file=SimpleUploadedFile("test.txt", b"dummy content", content_type="text/plain"))
    return Job.objects.create(file=file)
