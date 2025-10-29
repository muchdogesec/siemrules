import uuid
import pytest
from siemrules.siemrules.models import Profile


@pytest.fixture(autouse=True)
def default_profile(db):
    return Profile.objects.create(
        id=uuid.UUID("5e2c00bc-4e83-48b0-83dd-3fa084322245"),
        name="default-profile",
        is_default=True,
        ai_provider="openai",
    )
