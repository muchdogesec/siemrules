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

@pytest.fixture(autouse=True, scope="session")
def db_access_without_rollback_and_truncate(request, django_db_setup, django_db_blocker):
    django_db_blocker.unblock()

    from dogesec_commons.identity.serializers import IdentitySerializer
    from tests.src import data as test_data
    identity_s = IdentitySerializer(
        data=test_data.AUTHOR_1
    )
    identity_s.is_valid(raise_exception=True)
    identity = identity_s.save()
    identity.refresh_from_db()
    yield
    django_db_blocker.restore()