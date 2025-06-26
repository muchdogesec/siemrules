import copy
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, mock_open
from unittest import mock
import uuid
import pytest
from django.core.files.uploadedfile import InMemoryUploadedFile
from siemrules.siemrules import models
from siemrules.siemrules.correlations.models import RuleModel
from siemrules.siemrules.models import File
from siemrules.worker.tasks import (
    job_failed, new_correlation_task, new_task, process_correlation, process_report, run_txt2detection, run_file2txt, upload_to_arango, job_completed, upload_objects
)
from siemrules.worker import tasks
import stix2
from .utils import job



@pytest.mark.django_db
def test_new_task(job):
    file = job.file

    with patch("siemrules.worker.tasks.process_report.s") as mock_process_report, \
         patch("siemrules.worker.tasks.job_completed.si") as mock_error_task:
        
        new_task(job)

        mock_process_report.assert_called_once_with(file.file.name, job.id)
        mock_error_task.assert_called_once_with(job.id)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "job_type",
    [models.JobType.CORRELATION_PROMPT, models.JobType.CORRELATION_SIGMA],
)
def test_new_correlation_task(job: models.Job, job_type):
    related_indicators = mock.Mock()
    data = mock.Mock()
    correlation = mock.Mock()
    job.type = job_type
    with patch("siemrules.worker.tasks.process_correlation.s") as mock_process_correlation, \
        patch("siemrules.worker.tasks.process_correlation_ai.s") as mock_process_correlation_ai, \
         patch("siemrules.worker.tasks.job_completed.si") as mock_error_task:
        new_correlation_task(job, correlation, related_indicators, data)
        if job.type == models.JobType.CORRELATION_PROMPT:
            mock_process_correlation_ai.assert_called_once_with(job.id, data, related_indicators)
        if job.type == models.JobType.CORRELATION_SIGMA:
            mock_process_correlation.assert_called_once_with(job.id, correlation.model_dump(), related_indicators)
        mock_error_task.assert_called_once_with(job.id)

@pytest.mark.django_db
def test_process_correlation(job):
    correlation = mock.Mock()
    related_indicators = mock.Mock()
    with patch("siemrules.siemrules.correlations.models.RuleModel.model_validate") as mock_model_validate, \
        patch("siemrules.worker.tasks.upload_correlation") as mock_upload_correlation:

        tasks.process_correlation(job.id, correlation, related_indicators)
        mock_model_validate.assert_called_once_with(correlation)
        mock_upload_correlation.assert_called_once_with(mock_model_validate.return_value, related_indicators, job)
    
@pytest.mark.django_db
def test_upload_correlation(job):
    correlation = mock.Mock()
    related_indicators = mock.Mock()
    with patch("siemrules.siemrules.correlations.correlations.add_rule_indicator") as mock_add_rule_indicator, \
        patch("siemrules.worker.tasks.upload_objects") as mock_upload_objects:
        mock_add_rule_indicator.return_value = []
        tasks.upload_correlation(correlation, related_indicators, job)
        mock_add_rule_indicator.assert_called_once_with(correlation, related_indicators, job.type, job.data)
        mock_upload_objects.assert_called_once()
        mock_upload_objects.assert_called_once_with(job, mock_upload_objects.call_args[0][1], None, stix2arango_note=f"siemrules-correlation")

@pytest.mark.django_db
def test_process_correlation_ai(job):
    data = dict(author="some author", created="rule.date", modified="rule.modified", tlp_level="green", ai_provider="openai", prompt="some prompt")
    related_indicators = mock.Mock()
    with patch("siemrules.siemrules.correlations.models.RuleModel.model_validate") as mock_model_validate, \
        patch("siemrules.siemrules.correlations.correlations.generate_correlation_with_ai") as mock_generate_with_ai, \
        patch("siemrules.worker.tasks.parse_ai_model") as mock_parse_ai_model, \
        patch("siemrules.worker.tasks.upload_correlation") as mock_upload_correlation:
        mdump = mock_generate_with_ai.return_value.model_dump
        mdump.return_value = {}

        tasks.process_correlation_ai(job.id, data, related_indicators)
        mock_generate_with_ai.assert_called_once_with(mock_parse_ai_model.return_value, data['prompt'], related_indicators)
        mock_model_validate.assert_called_once_with(
            dict(
                **mdump.return_value,
                date="rule.date",
                modified="rule.modified",
                tags=["tlp.green"],
            )
        )
        mock_upload_correlation.assert_called_once_with(mock_model_validate.return_value, related_indicators, job)

@pytest.mark.django_db
def test_run_txt2detection():
    mock_file = mock.Mock(spec=File)
    mock_file.name = "test_file"
    mock_file.identity = {"type": "identity", "id": "identity--"+str(uuid.uuid4()), "name": "random identity", "identity_class": "organization"}
    mock_file.tlp_level = "TLP:WHITE"
    mock_file.id = "12345"
    mock_file.markdown_file.read.return_value = b"Test input text"
    mock_file.ai_provider = 'openai'
    mock_file.labels = []
    mock_file.references = mock_file.license = 'random'
    mock_file.level = "level"
    mock_file.status = "status"
    mock_file.created = "2022-11-13T12:43:41.613Z"
    mock_file.job = mock.Mock(spec=models.Job)
    mock_file_copy = copy.copy(mock_file)

    # Mock dependencies
    with mock.patch("siemrules.worker.tasks.parse_ai_model") as mock_parse_ai_model, \
         mock.patch("siemrules.worker.tasks.parse_stix") as mock_parse_stix, \
         mock.patch("txt2detection.run_txt2detection") as mock_run_txt2detection:
        
        mock_ai_provider = mock.Mock()
        mock_parse_ai_model.return_value = mock_ai_provider
        
        mock_stix_identity = stix2.Identity(**mock_file.identity)
        mock_parse_stix.return_value = mock_stix_identity

        mock_bundler = mock.Mock()
        mock_bundler.bundle_dict = {"mocked": "detection_output"}
        mock_run_txt2detection.return_value = mock_bundler

        # Run the function
        result = run_txt2detection(mock_file_copy)
        ##########
        mock_parse_ai_model.assert_called_once_with(mock_file_copy.ai_provider)
        mock_parse_stix.assert_called_once_with(mock_file_copy.identity)
        mock_run_txt2detection.assert_called_once_with(
            name=mock_file.name,
            identity=mock_stix_identity,
            tlp_level=mock_file.tlp_level,
            report_id=mock_file.id,
            ai_provider=mock_ai_provider,
            input_text="Test input text",
            labels=mock_file.labels,
            reference_urls=mock_file.references,
            license=mock_file.license,
            level=mock_file.level,
            status=mock_file.status,
            external_refs=[{'source_name': 'siemrules-created-type', 'external_id': mock_file.job.type}],
            created=mock_file.created,
        )

        assert result == {"mocked": "detection_output"}

@pytest.mark.django_db
def test_run_file2txt(job):
    with patch("tempfile.NamedTemporaryFile") as mock_tempfile, \
         patch("siemrules.worker.tasks.get_parser_class") as mock_parser_class, \
         patch("siemrules.worker.tasks.models.FileImage.objects.create") as mock_create_image:

        mock_parser_instance = MagicMock()
        mock_parser_instance.convert.return_value = "Extracted text"
        mock_parser_instance.images = {"image1.png": MagicMock()}
        mock_parser_class.return_value = MagicMock(return_value=mock_parser_instance)

        run_file2txt(job.file)

        mock_parser_instance.convert.assert_called_once()
        mock_create_image.assert_called_once()

@pytest.mark.django_db
def test_upload_to_arango(job):
    bundle = {"objects": []}
    from django.conf import settings

    with patch("siemrules.worker.tasks.Stix2Arango") as mock_s2a, \
         patch("siemrules.worker.tasks.db_view_creator.link_one_collection") as mock_db_view:

        mock_s2a_instance = MagicMock()
        mock_s2a.return_value = mock_s2a_instance

        upload_to_arango(job, bundle)

        mock_s2a.assert_called_once_with(
            file=None,
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
        mock_s2a_instance.run.assert_called_once()
        mock_db_view.assert_called()

@pytest.mark.django_db
def test_upload_objects(job):
    bundle = {"objects": []}
    from django.conf import settings
    mock_extra_data = {'key_x': 'value_y'}

    with patch("siemrules.worker.tasks.Stix2Arango") as mock_s2a:

        mock_s2a_instance = MagicMock()
        mock_s2a.return_value = mock_s2a_instance

        upload_objects(job, bundle, extra_data=mock_extra_data, bad_kwargs=None)

        mock_s2a.assert_called_once_with(
            file=None,
            database=settings.ARANGODB_DATABASE,
            collection=settings.ARANGODB_COLLECTION,
            host_url=settings.ARANGODB_HOST_URL,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
            bad_kwargs=None
        )
        assert 'key_x' in mock_s2a_instance.arangodb_extra_data
        mock_s2a_instance.run.assert_called_once()

@pytest.mark.django_db
def test_job_completed(job):
    job.state=models.JobState.PENDING
    job.save()

    with mock.patch('siemrules.siemrules.models.Job.objects.get', return_value=job):
        job_completed(job.id)

    job.refresh_from_db()
    assert job.state == models.JobState.COMPLETED
    assert job.pk == job.id


@pytest.mark.django_db
def test_job_failure(job):
    with mock.patch('siemrules.siemrules.models.Job.objects.get', return_value=job):
        job_failed(SimpleNamespace(id=uuid.uuid4()), None, None, job.id)
        assert job.state == models.JobState.FAILED

@pytest.mark.django_db
def test_process_report_success(job):

    with mock.patch("siemrules.worker.tasks.run_file2txt", return_value=None) as mock_run_file2txt, \
        mock.patch("siemrules.worker.tasks.run_txt2detection", return_value="detection_bundle") as mock_run_txt2detection, \
        mock.patch("siemrules.worker.tasks.upload_to_arango", return_value=None) as mock_upload_to_arango:

        process_report(job.file.name, job.id)

        job.refresh_from_db()
        mock_run_file2txt.assert_called_once_with(job.file)
        mock_run_txt2detection.assert_called_once_with(job.file)
        mock_upload_to_arango.assert_called_once_with(job, "detection_bundle")
        assert job.error is None
        assert job.state == models.JobState.PENDING


@pytest.mark.django_db
def test_process_report_fail(job):

    with mock.patch("siemrules.worker.tasks.run_file2txt", return_value=None, side_effect=ValueError("unexpected")) as mock_run_file2txt:
        with pytest.raises(ValueError):
            process_report(job.file.name, job.id)

        # Assertions
        job.refresh_from_db()
        mock_run_file2txt.assert_called_once_with(job.file)

