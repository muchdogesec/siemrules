import pytest


from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models


@pytest.fixture
def test_file(profile):
    """Create a test file."""
    return models.File.objects.create(
        name="test_file.txt",
        file=SimpleUploadedFile(
            "test_file.txt", b"test content", content_type="text/plain"
        ),
        profile=profile,
        identity_id="identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
    )


@pytest.fixture(scope="session")
def create_version():
    """Factory fixture to create versions with custom parameters."""

    def _create_version(
        file, rule_id="rule-001", modified="2024-01-01T00:00:00.000Z", **kwargs
    ):
        defaults = {
            "rule_id": rule_id,
            "modified": modified,
            "action": models.VersionAction.CREATE,
            "type": models.VersionTypes.PROMPT,
            "rule_type": models.VersionRuleType.BASE_RULE,
            "file": file,
        }
        defaults.update(kwargs)
        return models.Version.objects.create(**defaults)

    return _create_version
