
from unittest.mock import patch
from siemrules.siemrules import models
import pytest

@pytest.mark.django_db
def test_post_delete_file_signal(job, client):
    file: models.File = job.file
    with patch("siemrules.siemrules.reports.remove_report") as mock_remove_report:
        file_id = str(file.id)
        file.delete()
        mock_remove_report.assert_called_once_with("report--"+file_id)

@pytest.mark.django_db
def test_remove_file_on_job_failure_signal(job: models.Job, client):
    with patch("siemrules.siemrules.models.File.delete") as mock_delete_file:
        job.state = models.JobState.FAILED
        job.save()
        mock_delete_file.assert_called_once()

