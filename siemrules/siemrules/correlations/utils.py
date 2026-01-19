from datetime import datetime
from functools import lru_cache
import json
import uuid
import stix2
from datetime import datetime
import typing
import uuid

from django.conf import settings

if typing.TYPE_CHECKING:
    from siemrules import settings
from siemrules.siemrules.models import default_identity
from dogesec_commons.identity.models import Identity as CommonIdentity
from dogesec_commons.identity.serializers import IdentitySerializer


from dogesec_commons.objects.helpers import ArangoDBHelper

from rest_framework import request
from django.http import HttpRequest

@lru_cache(maxsize=256)
def get_stix_object(stix_id):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    binds = {
        "identity_id": stix_id,
    }
    query = """
    FOR doc IN siemrules_vertex_collection
    FILTER doc._is_latest == TRUE AND doc.id == @identity_id
    SORT doc.modified DESC, doc._record_modified DESC
    LIMIT 1
    RETURN KEEP(doc, KEYS(doc, TRUE))
    """
    return helper.execute_query(query, bind_vars=binds, paginate=False)

def  validate_author(author: str):
    if not author:
        author = 'identity--8ef05850-cb0d-51f7-80be-50e4376dbe63'
    if not isinstance(author, str):
        raise ValueError('author must be a string in format identity--<uuid>')
    if not author.startswith('identity--'):
        identity = make_identity(author)
        author = identity.id
        matched_identity = CommonIdentity.objects.filter(id=author)
        if not matched_identity.exists():
            s = IdentitySerializer(data=json.loads(identity.serialize()))
            s.is_valid(raise_exception=True)
            s.save()
        return author

    matched_identity = CommonIdentity.objects.filter(id=author)
    if not matched_identity.exists():
        raise ValueError(f'No identity found with id {author}')
    return author

def make_identity(name):
    return stix2.Identity(id='identity--'+str(uuid.uuid5(settings.STIX_NAMESPACE, f"txt2detection+{name}")), name=name, created_by_ref=default_identity()['id'], created=datetime(2020, 1, 1), modified=datetime(2020, 1, 1))
