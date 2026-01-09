import django.test
import django


import django.test
from unittest.mock import MagicMock, patch

from siemrules.siemrules.identities import delete_identity_cleanup
from siemrules.siemrules.models import File
from dogesec_commons.identity.models import Identity
from siemrules.siemrules.arangodb_helpers import ArangoDBHelper


url = "/api/v1/identities/"


def test_cleanup_signal(client: django.test.Client):
    identity_id = "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    collected_objects = dict()

    with patch("arango.database.StandardDatabase.collection") as mock_db_collection:
        delete_many: MagicMock = mock_db_collection.return_value.delete_many
        delete_identity_cleanup(Identity(id=identity_id))
        mock_db_collection.assert_any_call("siemrules_edge_collection")
        mock_db_collection.assert_any_call("siemrules_vertex_collection")
        delete_many.assert_called()

        objects_removed = 0
        for call in delete_many.mock_calls:
            objects_removed += len(delete_many.mock_calls[0].args[0])
        assert objects_removed > 10, "at least 10 objects must have been removed"


def test_delete_identity_calls_cleanup_signal(identities):
    identity_id = "identity--8ef05850-abcd-51f7-80be-50e4376dbe63"
    identity = Identity.objects.create(id=identity_id, stix=dict(name="Test Identity"))
    with patch(
        "siemrules.siemrules.identities.delete_identity_cleanup"
    ) as mock_cleanup_receiver:
        identity.delete()
        mock_cleanup_receiver.assert_called_once_with(
            identity,
        )


def test_identity_modify_calls_auto_update_signal(identities):
    identity_id = "identity--7b7c3431-429b-45c2-b4e8-9ceb8d2678a9"
    identity = Identity.objects.get(id=identity_id)
    with patch(
        "siemrules.siemrules.identities.auto_update_identities"
    ) as mock_auto_update_receiver:
        identity.stix["name"] = "Updated Test Identity"
        identity.save()
        mock_auto_update_receiver.assert_called_once_with(
            identity,
        )


def test_auto_update_identities(client: django.test.Client):
    identity_id = "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    identity = Identity.objects.get(id=identity_id)
    name = "Updated Test Identity via Auto Update"
    identity.stix["name"] = name
    identity.save()
    new_identity = client.get(url + identity_id + "/").data
    assert new_identity["name"] == name, "identity name must be updated"
    helper = ArangoDBHelper("siemrules_vertex_collection", None)
    arango_identities = helper.execute_query(
        f"""FOR doc IN siemrules_vertex_collection
    FILTER doc.id == @identity_id
    RETURN doc""",
        bind_vars={"identity_id": identity_id},
        paginate=False,
    )
    for arango_identity in arango_identities:
        assert (
            arango_identity["name"] == name
        ), "identity name in arangodb must be updated"


def test_list_identities(client: django.test.Client, subtests):
    response = client.get(url)
    identities = {obj["id"]: obj for obj in response.data["objects"]}
    for identity in identities.values():
        assert identity["type"] == "identity"
        identity_id = identity["id"]
        with subtests.test("test_retrieve_identity", identity_id=identity_id):
            assert identity == retrieve_identity(client, identity_id)


def retrieve_identity(client: django.test.Client, identity_id: str):
    response = client.get(url + identity_id + "/")
    identity = response.data
    assert identity["id"] == identity_id
    return identity
