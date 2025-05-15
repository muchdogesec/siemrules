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


from dogesec_commons.objects.helpers import ArangoDBHelper

from rest_framework import request
from django.http import HttpRequest

@lru_cache(maxsize=256)
def get_stix_object(stix_id):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    binds = {
        "@view": settings.VIEW_NAME,
        "identity_id": stix_id,
    }
    query = """
    FOR doc IN @@view
    SEARCH doc._is_latest == TRUE AND doc.id == @identity_id
    COLLECT id = doc.id INTO docs LET doc = docs[0].doc
    LIMIT 1
    RETURN KEEP(doc, KEYS(doc, TRUE))
    """
    return helper.execute_query(query, bind_vars=binds, paginate=False)

def  validate_author(author: str):
    if isinstance(author, dict):
        author = json.dumps(author)

    if author.startswith('{'):
        try:
            author = stix2.Identity(json.loads(author))
        except Exception as e:
            raise ValueError(f'invalid stix identity object: {e}')
    elif author.startswith('identity--'):
        _, _, _uuid = author.rpartition('--')
        try:
            uuid.UUID(_uuid)
        except:
            raise ValueError(f'invalid STIX id `{author}`')
        identities = get_stix_object(author)
        if len(identities) != 1:
            raise ValueError(f'identity `{author}` does not exist')
        author = stix2.parse(identities[0])
    else:
        author = make_identity(author)
    return author.serialize(sort_keys=False, indent=0)

def make_identity(name):
    return stix2.Identity(id='identity--'+str(uuid.uuid5(settings.STIX_NAMESPACE, f"txt2detection+{name}")), name=name, created_by_ref=default_identity()['id'], created=datetime(2020, 1, 1), modified=datetime(2020, 1, 1))
