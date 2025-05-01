
from unittest.mock import patch
from siemrules.siemrules import models
from tests.src.utils import job
import pytest

@pytest.mark.django_db
def test_post_delete_file_signal(job, client):
    file: models.File = job.file
    with patch("siemrules.siemrules.reports.remove_report") as mock_remove_report:
        file_id = str(file.id)
        file.delete()
        mock_remove_report.assert_called_once_with("report--"+file_id)