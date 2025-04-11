import io
from unittest.mock import patch, MagicMock, mock_open
from unittest import mock
import uuid
import pytest
import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile, SimpleUploadedFile
from siemrules.siemrules import models
from siemrules.siemrules.models import Job, File
from siemrules.worker.tasks import (
    new_task, process_post, save_file, run_txt2detection, run_file2txt, upload_to_arango, job_completed_with_error
)
import stix2

@pytest.fixture
@pytest.mark.django_db
def job():
    file = File.objects.create(name="test.txt", file=SimpleUploadedFile("test.txt", b"dummy content", content_type="text/plain"))
    return Job.objects.create(file=file)

@pytest.mark.django_db
def test_new_task(job):
    file = job.file

    with patch("siemrules.worker.tasks.process_post.s") as mock_process_post, \
         patch("siemrules.worker.tasks.job_completed_with_error.si") as mock_error_task:
        
        new_task(job)

        mock_process_post.assert_called_once_with(file.file.name, job.id)
        mock_error_task.assert_called_once_with(job.id)

@pytest.mark.django_db
def test_save_file():
    file_content = b"dummy content"
    file = InMemoryUploadedFile(
        file=mock_open(read_data=file_content)(),
        field_name="file",
        name="test.txt",
        content_type="text/plain",
        size=12,
        charset=None
    )

    with patch("tempfile.mkstemp", return_value=(123, "/tmp/mockfile.txt")), \
         patch("os.write") as mock_write:
        
        filename = save_file(file)
        
        assert filename == "/tmp/mockfile.txt"
        mock_write.assert_called_once_with(123, file_content)

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
    mock_file.status = 'unsupported'

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
        result = run_txt2detection(mock_file)
        ##########
        mock_parse_ai_model.assert_called_once_with(mock_file.ai_provider)
        mock_parse_stix.assert_called_once_with(mock_file.identity)
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
            status=mock_file.status,
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

    with patch("tempfile.NamedTemporaryFile") as mock_tempfile, \
         patch("siemrules.worker.tasks.Stix2Arango") as mock_s2a, \
         patch("siemrules.worker.tasks.db_view_creator.link_one_collection") as mock_db_view:
        mock_tempfile_instance = io.StringIO()
        mock_tempfile_instance.name = 'bundle.json'
        mock_tempfile.return_value = mock_tempfile_instance

        mock_s2a_instance = MagicMock()
        mock_s2a.return_value = mock_s2a_instance

        upload_to_arango(job, bundle)

        mock_s2a.assert_called_once_with(
            file=mock_tempfile_instance.name,
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
def test_job_completed_with_error(job):
    job.state=models.JobState.PENDING
    job.save()

    with mock.patch('siemrules.siemrules.models.Job.objects.get', return_value=job):
        job_completed_with_error(job.id)

    job.refresh_from_db()
    assert job.state == models.JobState.COMPLETED
    assert job.pk == job.id


@pytest.mark.django_db
def test_process_post_success(job):

    with mock.patch("siemrules.worker.tasks.run_file2txt", return_value=None) as mock_run_file2txt, \
        mock.patch("siemrules.worker.tasks.run_txt2detection", return_value="detection_bundle") as mock_run_txt2detection, \
        mock.patch("siemrules.worker.tasks.upload_to_arango", return_value=None) as mock_upload_to_arango:

        process_post(job.file.name, job.id)

        job.refresh_from_db()
        mock_run_file2txt.assert_called_once_with(job.file)
        mock_run_txt2detection.assert_called_once_with(job.file)
        mock_upload_to_arango.assert_called_once_with(job, "detection_bundle")
        assert job.error is None
        assert job.state == models.JobState.PENDING


@pytest.mark.django_db
def test_process_post_fail(job):

    with mock.patch("siemrules.worker.tasks.run_file2txt", return_value=None, side_effect=ValueError("unexpected")) as mock_run_file2txt:

        process_post(job.file.name, job.id)

        # Assertions
        job.refresh_from_db()
        mock_run_file2txt.assert_called_once_with(job.file)
        assert job.error is not None
        assert job.state == models.JobState.PENDING

