import os
from django.conf import settings
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid, typing
# import txt2stix, txt2stix.extractions
from django.core.exceptions import ValidationError
from datetime import datetime, timezone
from django.core.files.uploadedfile import InMemoryUploadedFile
import stix2
from .utils import TLP_Levels, TLP_LEVEL_STIX_ID_MAPPING
from file2txt.parsers.core import BaseParser

# Create your models here.

def validate_extractor(types, name):
    pass

def create_report_id():
    return ""

def default_identity():
    return settings.STIX_IDENTITY

def validate_identity(value):
    try:
        identity = stix2.Identity(**value)
        value["id"] = identity.id
    except BaseException as e:
        raise ValidationError(f"Invalid Identity: {e}")
    return True


def upload_to_func(instance: 'File|FileImage', filename):
    if isinstance(instance, FileImage):
        instance = instance.report
    return os.path.join(str(instance.identity['id']), str(instance.report_id), filename)

def validate_file(file: InMemoryUploadedFile, mode: str):
    _, ext = os.path.splitext(file.name)
    ext = ext[1:]
    if ext not in BaseParser.PARSERS[mode][2]:
        raise ValidationError(f"Unsupported file extension `{ext}`")
    return True

class File(models.Model):
    id = models.UUIDField(unique=True, max_length=64, primary_key=True, default=uuid.uuid4)
    name = models.CharField(max_length=256, help_text="This will be assigned to the File and Report object created. Note, the names of each detection rule generated will be automatic. Max 256 characters. This is a txt2detection setting.")
    identity = models.JSONField(default=default_identity, validators=[validate_identity])
    labels = ArrayField(base_field=models.CharField(max_length=256), default=list)
    tlp_level = models.CharField(choices=TLP_Levels.choices, default=TLP_Levels.RED, max_length=128)
    file = models.FileField(max_length=1024, upload_to=upload_to_func)
    mimetype = models.CharField(max_length=512)
    mode = models.CharField(max_length=256)
    defang = models.BooleanField(default=True, help_text="Whether to defang the observables in the blog. e.g. turns 1.1.1[.]1 to 1.1.1.1 for extraction. This is a file2txt setting. This is a file2txt setting. Default is `true`.")
    extract_text_from_image = models.BooleanField(default=True)
    ai_provider = models.CharField(max_length=256, null=True)
    markdown_file = models.FileField(max_length=512, upload_to=upload_to_func, null=True)

    created = models.DateTimeField(auto_now_add=True)

    references = ArrayField(base_field=models.URLField(), default=list, null=True)
    license = models.CharField(max_length=256, null=True, default=None, blank=True)

    ignore_embedded_relationships = models.BooleanField(default=False)
    ignore_embedded_relationships_sro = models.BooleanField(default=False)
    ignore_embedded_relationships_smo = models.BooleanField(default=False)

    
    @property
    def report_id(self):
        return 'report--'+str(self.id)
    
    @report_id.setter
    def report_id(self, value):
        self.id = value

    def clean(self) -> None:
        validate_file(self.file, self.mode)
        return super().clean()
    
    def __str__(self) -> str:
        return f"File(id={self.id})"

@receiver(post_delete, sender=File)
def remove_reports_on_delete(sender, instance: File, **kwargs):
    from .reports import remove_report
    remove_report(instance.report_id)


class FileImage(models.Model):
    report = models.ForeignKey(File, related_name='images', on_delete=models.CASCADE)
    image = models.ImageField(upload_to=upload_to_func, max_length=256)
    name = models.CharField(max_length=256)



class JobState(models.TextChoices):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"

class JobType(models.TextChoices):
    FILE = "file"
    CORRELATION = "correlation"


class Job(models.Model):
    type = models.CharField(choices=JobType.choices, max_length=20, default=JobType.FILE)
    file = models.OneToOneField(File, on_delete=models.CASCADE, default=None, null=True)
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    state = models.CharField(choices=JobState.choices, max_length=20, default=JobState.PENDING)
    error = models.CharField(max_length=65536, null=True)
    run_datetime = models.DateTimeField(auto_now_add=True)
    completion_time = models.DateTimeField(null=True, default=None)
    data = models.JSONField(default=None, null=True)

    def save(self, *args, **kwargs) -> None:
        if not self.completion_time and self.state == JobState.COMPLETED:
            self.completion_time = datetime.now(timezone.utc)
        return super().save(*args, **kwargs)
