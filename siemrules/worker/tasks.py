import io
import json
import logging
import os
from pathlib import Path
from siemrules.siemrules.models import Job, File
from siemrules.siemrules import models
from celery import shared_task
from txt2detection.utils import validate_token_count, parse_model as parse_ai_model
from txt2detection.bundler import Bundler as txt2detectionBundler
import txt2detection
from file2txt.converter import Fanger, get_parser_class
from file2txt.parsers.core import BaseParser
from django.conf import settings
import typing
if typing.TYPE_CHECKING:
    from siemrules import settings


from stix2 import parse as parse_stix
from dogesec_commons.objects import db_view_creator


import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import File as DjangoFile
from django.core.files.base import File as DjangoFile
from stix2arango.stix2arango import Stix2Arango

POLL_INTERVAL = 1


def new_task(job: Job, file: File):
    ( process_post.s(file.file.name, job.id) | job_completed_with_error.si(job.id)).apply_async(
        countdown=POLL_INTERVAL, root_id=str(job.id), task_id=str(job.id)
    )


def save_file(file: InMemoryUploadedFile):
    filename = Path(file.name).name
    print("name=", file.name, filename)
    fd, filename = tempfile.mkstemp(suffix='--'+filename, prefix='file--')
    os.write(fd, file.read())
    return filename

def run_txt2detection(file: models.File):
    provider = parse_ai_model(file.ai_provider)
    input_str = file.markdown_file.read().decode()
    bundler: txt2detectionBundler = txt2detection.run_txt2detection(
        name=file.name,
        identity=parse_stix(file.identity),
        tlp_level=file.tlp_level,
        confidence=file.confidence,
        labels=file.labels,
        report_id=file.id,
        ai_provider=provider,
        input_text=input_str,
        reference_urls=file.references,
        license=file.license,
        status=file.status,
    )
    return bundler.bundle_dict

def run_file2txt(file: models.File):
    with tempfile.NamedTemporaryFile('rb+') as f:
        f.write(file.file.read())
        f.flush()
        f.seek(0)

        parser_class = get_parser_class(file.mode, file.file.name)
        converter: BaseParser = parser_class(f.name, file.mode, file.extract_text_from_image, settings.GOOGLE_VISION_API_KEY)
        output = converter.convert()
        if file.defang:
            output = Fanger(output).defang()

        file.markdown_file.save('markdown.md', io.StringIO(output), save=True)

        models.FileImage.objects.filter(report=file).delete()
        for name, img in converter.images.items():
            img_file = io.BytesIO()
            img_file.name = name
            img.save(img_file, format='png')
            # images.append(img_file)
            models.FileImage.objects.create(report=file, image=DjangoFile(img_file, name), name=name)
        
        return 

def upload_to_arango(job: models.Job, bundle: dict, link_collection=True):
    with tempfile.NamedTemporaryFile('w+') as f:
        f.write(json.dumps(bundle))
        f.flush()
        f.seek(0)
    
        s2a = Stix2Arango(
            file=str(f.name),
            database=settings.ARANGODB_DATABASE,
            collection=settings.ARANGODB_COLLECTION,
            stix2arango_note=f"siemrules-file--{job.file.id}",
            host_url=settings.ARANGODB_HOST_URL,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
            ignore_embedded_relationships=job.file.ignore_embedded_relationships,
            ignore_embedded_relationships_sro=job.file.ignore_embedded_relationships_sro,
            ignore_embedded_relationships_smo=job.file.ignore_embedded_relationships_smo,
        )
        s2a.arangodb_extra_data = dict(_stixify_report_id=job.file.report_id)
        if link_collection:
            db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{settings.ARANGODB_COLLECTION}_edge_collection")
            db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{settings.ARANGODB_COLLECTION}_vertex_collection")
        s2a.run()


@shared_task
def process_post(filename, job_id, *args):
    job = Job.objects.get(id=job_id)
    try:
        run_file2txt(job.file)
        bundle = run_txt2detection(job.file)
        upload_to_arango(job, bundle)
        job.file.save()
    except Exception as e:
        job.error = f"report failed to process with: {e}"
        logging.error(job.error)
        logging.exception(e)
    job.save()
    return job_id


@shared_task
def job_completed_with_error(job_id):
    job = Job.objects.get(pk=job_id)
    job.state = models.JobState.COMPLETED
    job.save()
