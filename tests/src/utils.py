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
