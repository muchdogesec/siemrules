import io
import json
import logging
import os
from pathlib import Path
import uuid
from siemrules.siemrules.correlations import correlations
from siemrules.siemrules.correlations.models import RuleModel
from siemrules.siemrules.models import Job, File, JobType
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
from rest_framework import validators

from stix2 import parse as parse_stix, Bundle
from stix2.serialization import serialize as stix2_serialize
from dogesec_commons.objects import db_view_creator


import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import File as DjangoFile
from django.core.files.base import File as DjangoFile
from stix2arango.stix2arango import Stix2Arango

POLL_INTERVAL = 1


def new_task(job: Job):
    task = process_post.s(job.file.file.name, job.id)
    ( task| job_completed_with_error.si(job.id)).apply_async(
        countdown=POLL_INTERVAL, root_id=str(job.id), task_id=str(job.id)
    )

def new_correlation_task(job: Job, correlation: RuleModel, related_indicators, data):
    assert job.type == JobType.CORRELATION
    match job.data['input_form']:
        case 'sigma':
            task = process_correlation.s(job.id, correlation.model_dump(by_alias=True), related_indicators)
        case 'ai_prompt':
            task = process_correlation_ai.s(job.id, data, related_indicators)
        case _:
            raise validators.ValidationError('Unknown job type')
    # process_correlation(job.id, correlation.model_dump(by_alias=True), extra_documents)
    ( 
        task| job_completed_with_error.si(job.id)).apply_async(
        countdown=POLL_INTERVAL, root_id=str(job.id), task_id=str(job.id)
    )

def save_file(file: InMemoryUploadedFile):
    filename = Path(file.name).name
    print("name=", file.name, filename)
    fd, filename = tempfile.mkstemp(suffix='--'+filename, prefix='file--')
    os.write(fd, file.read())
    return filename

def run_txt2detection(file: models.File):
    input_str = None
    provider = None
    kwargs = {}
    if file.mode == 'sigma':
        kwargs['sigma_file'] = file.file.read().decode()
    else:
        input_str = file.markdown_file.read().decode()
        provider = parse_ai_model(file.ai_provider)

    bundler: txt2detectionBundler = txt2detection.run_txt2detection(
        name=file.name,
        identity=parse_stix(file.identity),
        tlp_level=file.tlp_level,
        labels=file.labels,
        report_id=file.id,
        ai_provider=provider,
        input_text=input_str,
        reference_urls=file.references,
        license=file.license,
        **kwargs,
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
    upload_objects(
            job, bundle, 
            extra_data=dict(_stixify_report_id=job.file.report_id, _siemrules_job_id=str(job.id)),
            ignore_embedded_relationships=job.file.ignore_embedded_relationships,
            ignore_embedded_relationships_sro=job.file.ignore_embedded_relationships_sro,
            ignore_embedded_relationships_smo=job.file.ignore_embedded_relationships_smo,
            stix2arango_note=f"siemrules-file--{job.file.id}",
            link_collection=link_collection,
    )
    

def upload_objects(job: models.Job, bundle, extra_data: dict, link_collection=False, **kwargs):
    s2a = Stix2Arango(
        file=None,
        database=settings.ARANGODB_DATABASE,
        collection=settings.ARANGODB_COLLECTION,
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        **kwargs
    )
    s2a.arangodb_extra_data = {**(extra_data or  {}), '_siemrules_job_id':str(job.id)}
    if link_collection:
        db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{settings.ARANGODB_COLLECTION}_edge_collection")
        db_view_creator.link_one_collection(s2a.arango.db, settings.VIEW_NAME, f"{settings.ARANGODB_COLLECTION}_vertex_collection")

    s2a.run(data=bundle)
    return s2a


def make_bundle(objects):
    return json.loads(stix2_serialize(dict(type="bundle", id="bundle--"+str(uuid.uuid4()), objects=objects)))


@shared_task
def process_post(filename, job_id, *args):
    job = Job.objects.get(id=job_id)
    try:
        if job.file.mode == 'sigma':
            pass
        else:
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
def process_correlation(job_id, correlation: RuleModel, extra_documents):
    correlation = RuleModel.model_validate(correlation)
    job = Job.objects.get(id=job_id)
    
    upload_correlation(correlation, extra_documents, job)

def upload_correlation(correlation, extra_documents, job: Job):
    objects = correlations.add_rule_indicator(correlation, extra_documents, job.data['input_form'], job.data)
    upload_objects(job, make_bundle(objects), None, stix2arango_note=f"siemrules-correlation")

@shared_task
def process_correlation_ai(job_id, data, extra_documents):
    job = Job.objects.get(id=job_id)
    model = parse_ai_model(data["ai_provider"])
    correlation = correlations.generate_correlation_with_ai(model, data['prompt'], extra_documents)
    correlation_with_date = RuleModel.model_validate(
        dict(
            **correlation.model_dump(),
            author=data.get('author'),
            date=data.get('created'),
            modified=data.get('modified'),
            tags=["tlp."+data['tlp_level'].replace('_', '-')],
        )
    )
    upload_correlation(correlation_with_date, extra_documents, job)



@shared_task
def job_completed_with_error(job_id):
    job = Job.objects.get(pk=job_id)
    job.state = models.JobState.COMPLETED
    job.save()
