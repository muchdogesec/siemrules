### This is for testing functions that remove objects from arangodb
import pytest

from siemrules.siemrules.arangodb_helpers import request_from_queries
from siemrules.siemrules.reports import remove_report
from dogesec_commons.objects.helpers import ArangoDBHelper


@pytest.mark.parametrize(
    "report_id",
    [
        "report--8af82832-2abd-5765-903c-01d414dae1e9"
    ]
)
def test_remove_report(report_id):
    remove_report(report_id)
    helper = ArangoDBHelper('', request_from_queries())
    for collection in ['siemrules_vertex_collection', 'siemrules_edge_collection']:
        for obj in helper.db.collection(collection).all():
            assert obj.get('_stixify_report_id') != report_id, f'all objects with _stixify_report_id == {report_id} should already be deleted'