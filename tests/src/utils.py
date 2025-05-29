from itertools import tee
from operator import lt
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules.models import Job, File

def is_sorted(iterable, key=None, reverse=False):
    it = iterable if (key is None) else map(key, iterable)
    a, b = tee(it)
    next(b, None)
    if reverse:
        b, a = a, b
    return not any(map(lt, b, a))

@pytest.fixture
def job():
    file = File.objects.create(name="test.txt", file=SimpleUploadedFile("test.txt", b"dummy content", content_type="text/plain"))
    return Job.objects.create(file=file)


@pytest.fixture
def celery_eager():
    from siemrules.worker.celery import app
    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False