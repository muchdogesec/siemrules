import django.test
import django


import django.test
from unittest.mock import MagicMock, patch


url = "/api/v1/identities/"
def test_destroy_identity(client: django.test.Client):
    identity_id = "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63"
    collected_objects = dict()

    with patch("siemrules.siemrules.models.File.objects.filter") as mock_filter_file, \
        patch('arango.database.StandardDatabase.collection') as mock_db_collection:
        delete_many: MagicMock = mock_db_collection.return_value.delete_many
        mock_filter_file_delete: MagicMock = mock_filter_file.return_value.delete
        response = client.delete(url + identity_id + "/")
        assert response.status_code == 204
        mock_filter_file.assert_called_once_with(identity__id=identity_id)
        mock_db_collection.assert_any_call("siemrules_edge_collection")
        mock_db_collection.assert_any_call("siemrules_vertex_collection")
        delete_many.assert_called()
        mock_filter_file_delete.assert_called_once()

        objects_removed = 0
        for call in delete_many.mock_calls:
            objects_removed += len(delete_many.mock_calls[0].args[0])
        assert objects_removed > 10, "at least 10 objects must have been removed"


def test_list_identities(client: django.test.Client, subtests):
    response = client.get(url)
    identities = {obj['id']: obj for obj in response.data['objects']}
    for identity in identities.values():
        assert identity['type'] == 'identity'
        identity_id = identity['id']
        with subtests.test('test_retrieve_identity', identity_id=identity_id):
            assert identity == retrieve_identity(client, identity_id)


def retrieve_identity(client: django.test.Client, identity_id: str):
    response = client.get(url+identity_id+'/')
    identity = response.data['objects'][0]
    assert identity['id'] == identity_id
    return identity