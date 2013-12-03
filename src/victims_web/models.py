# This file is part of victims-web.
#
# Copyright (C) 2013 The Victims Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Data models.
"""

import datetime
import json

from abc import ABCMeta, abstractproperty
from copy import deepcopy
from os import urandom, remove
from os.path import isfile
from hashlib import sha1, sha512
from hmac import HMAC
from uuid import uuid4
from bson.dbref import DBRef

from flask.ext.bcrypt import generate_password_hash
from flask.ext.mongoengine import Document
from mongoengine import (
    StringField, DateTimeField, DictField, BooleanField, EmbeddedDocument,
    EmbeddedDocumentField, ListField, EmailField, MapField, ReferenceField,
    ObjectIdField
)

from victims_web.config import (
    BCRYPT_LOG_ROUNDS, SUBMISSION_GROUPS, HASHING_ALGORITHMS
)


def generate_client_secret(apikey):
    return HMAC(bytes(urandom(24)), apikey, sha1).hexdigest().upper()


def generate_apikey(username):
    apikey = HMAC(uuid4().hex, username).hexdigest()
    return apikey.upper()


def generate_api_tokens(username):
    apikey = generate_apikey(username)
    secret = generate_client_secret(apikey)
    return (apikey, secret)


def group_choices():
    choices = []
    for group in SUBMISSION_GROUPS.keys():
        choices.append((group, group))
    return choices


def group_coordinates():
    keys = []
    for coords in SUBMISSION_GROUPS.values():
        for key in coords:
            if key not in keys:
                keys.append(key)
    return keys


class RestrictedDict(dict):
    __metaclass__ = ABCMeta

    @abstractproperty
    def validkeys(self):
        raise NotImplementedError

    def __setitem__(self, key, val):
        if key not in self.validkeys:
            raise KeyError
        print(key)
        dict.__setitem__(self, key, val)


class ValidatedDocument(Document):
    """
    Extended MongoEngine document which can use custom validators.
    """

    _pre_save_hooks = []

    meta = {
        'allow_inheritance': False,
        'abstract': True
    }

    def save(self, *args, **kwargs):
        """
        Saves the document to the database.

        :Parameters:
           - `args`: All non-keyword args.
           - `kwargs`: All keyword args.
        """
        for hook in self._pre_save_hooks:
            hook(self)

        super(ValidatedDocument, self).save(*args, **kwargs)


class JsonifyMixin(object):

    def jsonify(self, fields=None):
        """
        Converts an instance into json.
        """

        def handle_special_objs(obj):
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            elif isinstance(obj, DBRef):
                return str(Account.objects.get(id=obj.id).username)
            return str(obj)

        data = self.to_mongo()

        # workaround to remove default values when using only(*fields)
        # Note that this will not work for embedded documents with defaults
        if fields:
            fields = [
                self.jsonname(f.split('.', 1)[0].strip()) for f in fields
            ]

        for key in data.keys():
            if key.startswith('_') or (fields and key not in fields):
                if key in data:
                    del data[key]

        return json.dumps(data, default=handle_special_objs)

    def mongify(self, data):
        """
        Populates this instance from a dictionary loaded from a JSON string.
        Only known fields are populated.
        """
        for field in self._db_field_map:
            if field not in data:
                continue

            value = data[field]

            if isinstance(self._fields[field], EmbeddedDocumentField):
                tmp = self._fields[field].document_type_obj()
                tmp.mongify(value)
                value = tmp

            setattr(self, field, value)

    @classmethod
    def fields(cls):
        """
        Helper method to get fieldnames available in this document.
        """
        return [
            field for field in cls._db_field_map if not field.startswith('_')
        ]

    @classmethod
    def modelname(cls, injson):
        """
        Convert JSON fieldname (DB name) to Model fieldname. If no match found,
        the input fieldname is retured.
        """
        if injson in cls._db_field_map.values():
            for field in cls._db_field_map.keys():
                if injson == cls._db_field_map[field]:
                    return field
        return injson

    @classmethod
    def jsonname(cls, inmodel):
        """
        Convert a Model fieldname to a JSON fieldname. If no match found, the
        input fieldname is returned.
        """
        return cls._db_field_map.get(inmodel, inmodel)

    def keys(self):
        fields = []
        for field in self.fields():
            if self[field] is not None:
                fields.append(field)
        return fields


class Account(ValidatedDocument):
    """
    A user account.
    """
    meta = {'collection': 'users'}

    username = StringField(regex='^[a-zA-Z0-9_\-\.]*$', required=True)
    password = StringField(required=True)
    email = EmailField()
    roles = ListField(
        StringField(choices=(
            ('admin', 'Administrator'),
            ('moderator', 'Moderator'),
            ('trusted_submitter', 'Trusted Submitter'),
        )),
        default=[]
    )
    active = BooleanField(default=False)
    createdon = DateTimeField(default=datetime.datetime.utcnow)
    lastlogin = DateTimeField()
    lastip = StringField()
    apikey = StringField(min_length=32, max_length=32)
    secret = StringField(min_length=40, max_length=40)
    lastapi = DateTimeField()

    def __str__(self):
        return str(self.username)

    def update_api_tokens(self):
        (self.apikey, self.secret) = generate_api_tokens(self.username)

    def set_password(self, plain):
        self.password = generate_password_hash(plain, BCRYPT_LOG_ROUNDS)

    def save(self, *args, **kwargs):
        if self.apikey is None or len(self.apikey) == 0:
            self.update_api_tokens()
        ValidatedDocument.save(self, *args, **kwargs)


class Removal_(JsonifyMixin, ValidatedDocument):
    """
    A removal entry
    """
    meta = {'collection': 'removals'}

    date = DateTimeField(default=datetime.datetime.utcnow)
    hash = StringField(regex='^[a-fA-F0-9]*$')
    group = StringField(choices=group_choices())
    reason = StringField(
        choices=(
            ('DELETE', 'DELETE'),
            ('WRONG', 'WRONG'),
            ('UPDATE', 'UPDATE')
        ),
        default='DELETE'
    )


class CVE(JsonifyMixin, EmbeddedDocument):
    """
    A CVE record for embedded use.
    """
    id = StringField(required=True)
    addedon = DateTimeField(default=datetime.datetime.utcnow, required=True)


class JsonMixin(object):
    """
    JSON mixin
    """
    JSON_SKIP = []

    def _handle_special_objs(self, obj):
        """
        Handle JSON string generation for 'special' objects.

        :param obj: Document field's PyObject representation
        :rtype: string
        """
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return str(obj)

    @property
    def json_skip(self):
        """
        Overide this property to skip fields when generating JSON string
        """
        return self.JSON_SKIP

    def jsonify(self):
        """
        Get JSON string representation of this Document instance.
        """
        return json.dumps(self.mongify(), default=self._handle_special_objs)

    def mongify(self, raw=False):
        """
        Return a json friendly filtered python dict

        :param raw: Return the raw `to_mongo` return value of the `Document`.
            Defaults to False.
        :type raw: bool
        """
        if raw:
            return self.to_mongo()

        result = {}
        for key in self._fields:
            if key not in self.json_skip:
                value = getattr(self, key)
                if isinstance(value, JsonMixin):
                    value = value.mongify()
                if value is not None:
                    result[key] = value
        return result


class UpdateableDocument(JsonMixin, ValidatedDocument):
    """
    An abstract document to handle models that are updatable. Provides fields
    like group, created and modified.
    """
    meta = {
        'allow_inheritance': False,
        'abstract': True
    }

    group = StringField()
    created = DateTimeField(default=datetime.datetime.utcnow)
    modified = DateTimeField(default=datetime.datetime.utcnow)

    @property
    def json_skip(self):
        return super(UpdateableDocument, self).json_skip + [
            'group', 'created', 'modified'
        ]

    @property
    def is_dirty(self):
        """
        Helper method to determine if document has changed fields.
        """
        return hasattr(self, '_changed_fields') \
            and len(self._changed_fields) > 0

    @property
    def is_new(self):
        """
        Helper method to determine if document is new (user created).
        """
        return hasattr(self, '_created') and self._created

    def on_create(self):
        """
        Additional create actions to perform if document is new. By default
        does nothing.
        """
        pass

    def on_update(self):
        """
        Additional update actions to perform if document is dirty. By default
        does nothing.
        """
        pass

    def on_delete(self):
        """
        Additional delete actions to perform if document deletion succeeds. By
        default does nothing.
        """
        pass

    def save(self, *args, **kwargs):
        """
        A save wrapper that ensures the modified timestamp is updated if
        changes exists.
        """
        if self.is_new:
            self.on_create()

        if self.is_dirty:
            # update modified timestamp
            self.modified = datetime.datetime.utcnow()
            self.on_update()
        super(UpdateableDocument, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        A delete wrapper that creates a new Removal document once deletion
        succeeds.
        """
        super(UpdateableDocument, self).delete(*args, **kwargs)
        # post deletion, add a delete entry
        Removal(
            oid=self.id,
            group=self.group,
            collection=self._meta['collection']
        ).save()
        self.on_delete()


class Fingerprint(UpdateableDocument):
    """
    A document to contain an artifact's Victims fingerprtint.
    """
    meta = {'collection': 'fingerprints'}

    uuid = StringField(default=None)
    files = DictField()

    def update_uuid(self):
        """
        Update the document's uuid based. The uuid is a SHA-512 sum of all file
        fingerprints sorted and combined.
        """
        h = sha512()
        for key in sorted(self.files.keys()):
            h.update(key)
        self.uuid = h.hexdigest()

    def on_create(self):
        self.update_uuid()

    def on_update(self):
        self.update_uuid()


class Artifact(UpdateableDocument):
    """
    An artifact document contains artifact checksum in multiple algorithms and
    referes to a victims fingerprint document associated with the file.
    """
    meta = {'collection': 'artifacts'}

    checksums = MapField(field=StringField())
    fingerprint = ReferenceField(Fingerprint, default=None)


class Record(UpdateableDocument):
    """
    A record document is the meta container holding CVE, coordinate and other
    information pertaining to an approved submission.
    """
    meta = {'collection': 'records'}

    coordinates = DictField(default=None)
    cves = ListField(required=True)
    filename = StringField(default=None)
    artifact = ReferenceField(Artifact)


class Removal(UpdateableDocument):
    """
    A removal document maintains history on all UpdateableDocument's that were
    deleted.
    """
    # TODO: rename collection name
    meta = {'collection': 'removals_'}

    oid = ObjectIdField()
    group = StringField()
    collection = StringField()


class CoordinateDict(RestrictedDict):

    @property
    def validkeys(self):
        return group_coordinates()


class HashesDict(RestrictedDict):

    @property
    def validkeys(self):
        return HASHING_ALGORITHMS


class Hash(JsonifyMixin, EmbeddedDocument, ValidatedDocument):
    """
    A hash record.
    """
    meta = {'collection': 'hashes'}

    # Temporary item for v1 mapping
    _v1 = DictField(default={})
    date = DateTimeField(default=datetime.datetime.utcnow)
    createdon = DateTimeField(default=datetime.datetime.utcnow)
    hash = StringField(regex='^[a-fA-F0-9]*$')
    name = StringField()
    version = StringField(default='UNKNOWN')
    coordinates = DictField(basecls=CoordinateDict(), default=None)
    group = StringField(choices=group_choices())
    format = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    hashes = DictField(basecls=HashesDict(), default=None)
    vendor = StringField(default='UNKNOWN')
    cves = ListField(EmbeddedDocumentField(CVE), default=[])
    status = StringField(
        choices=(('SUBMITTED', 'SUBMITTED'), ('RELEASED', 'RELEASED')),
        default='SUBMITTED')
    metadata = ListField(DictField(), db_field='meta', default=[])
    submitter = StringField()
    submittedon = DateTimeField(default=datetime.datetime.utcnow)

    def cve_list(self):
        """
        Get the CVE(s) associated with this hash object as a list.
        """
        cves = []
        for cve in self.cves:
            cves.append(cve.id)
        return cves

    def append_cves(self, cves=[]):
        """
        Append a list of cves to this instance. The current datetime is used.
        """
        cvelist = [cve.id for cve in self.cves]
        for cve in cves:
            if cve not in cvelist:
                self.cves.append(CVE(id=cve))

    def jsonify(self, fields=None):
        """
        Update jsonify to flatten some fields.
        """
        self.cves = self.cve_list()
        return JsonifyMixin.jsonify(self, fields)

    def mongify(self, data):
        """
        Load from json
        """
        obj = data

        if 'cves' in obj:
            self.append_cves(obj['cves'])
            obj.pop('cves', None)

        JsonifyMixin.mongify(self, obj)

    def notify_change(self, reason='DELETE'):
        if self.status == 'RELEASED':
            removal = Removal_(hash=self.hash, group=self.group, reason=reason)
            removal.save()

    def save(self, *args, **kwargs):
        """
        Ensure that the date is updated
        """
        self.date = datetime.datetime.utcnow()
        ValidatedDocument.save(self, *args, **kwargs)
        self.notify_change('UPDATE')

    def delete(self, *args, **kwargs):
        """
        Update the removals collection when a document is deleted
        """
        ValidatedDocument.delete(self, *args, **kwargs)
        self.notify_change()


class Submission(JsonifyMixin, ValidatedDocument):
    """
    A Submission Hash
    """
    meta = {'collection': 'submissions'}

    submitter = StringField()
    submittedon = DateTimeField(default=datetime.datetime.utcnow)
    source = StringField()
    filename = StringField()
    format = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    metadata = DictField(default={})
    coordinates = DictField(basecls=CoordinateDict(), default=None)
    cves = ListField(StringField())
    group = StringField(choices=group_choices())
    comment = StringField()
    approval = StringField(
        choices=(
            ('REQUESTED', 'REQUESTED'),
            ('PENDING_APPROVAL', 'PENDING APPROVAL'),
            ('APPROVED', 'APPROVED'),
            ('IN_DATABASE', 'IN DATABASE'),
            ('DECLINED', 'DECLINED'),
            ('INVALID', 'INVALID')
        ),
        default='REQUESTED'
    )
    entry = EmbeddedDocumentField(Hash, default=None)

    def remove_source_file(self, nosave=False, silent=False):
        try:
            if not isfile(self.source):
                return
            remove(self.source)
            self.source = '<source deleted>'
            if not silent:
                self.add_comment('Source file deleted')
            if not nosave:
                ValidatedDocument.save(self)
        except:
            if not silent:
                self.add_comment('Source file deletion failed')

    def push_to_db(self):
        new_hash = deepcopy(self.entry)
        new_hash.id = None
        new_hash.status = 'RELEASED'
        new_hash.submitter = self.submitter
        new_hash.submittedon = self.submittedon
        if self.filename:
            new_hash.name = self.filename
        if self.format:
            new_hash.format = self.format
        if len(self.metadata) > 0:
            new_hash.metadata.append({
                'properties': self.metadata,
                'filename': 'victims.submission',
            })
        new_hash.append_cves(self.cves)
        new_hash.group = self.group
        new_hash.save()

    def add_comment(self, comment):
        if self.comment and len(self.comment.strip()) > 0:
            self.comment += '\n'
        else:
            self.comment = ''
        now = datetime.datetime.utcnow().isoformat()
        self.comment += '[%s] %s' % (now, comment)
        # make sure comments are saved instantaneously
        ValidatedDocument.save(self)

    def valid_entry(self):
        if (not self.group
                or len(self.group.strip()) == 0):
            self.add_comment('[auto] no group specified')
            return False
        if len(self.cves) == 0:
            self.add_comment('[auto] no cves provided')
            return False
        if self.entry.hash and len(self.entry.hash.strip()) > 0:
            return True
        if len(self.entry.hashes) == 0:
            self.add_comment('[auto] no hashes provided')
            return False
        return True

    def rule_check(self):
        if self.approval in ['REQUESTED', 'PENDING_APPROVAL']:
            if self.entry is not None and self.submitter:
                user = Account.objects(username=self.submitter).first()
                if user:
                    for role in ['admin', 'moderator', 'trusted_submitter']:
                        if role in user.roles:
                            self.add_comment('[auto] trusted user')
                            return True
        return False

    def pre_save_hook(self):
        if self.approval == 'APPROVED' or self.rule_check():
            if self.entry is not None:
                if not self.valid_entry():
                    # we cannot autopush
                    self.approval = 'INVALID'
                    return None
                # Add a new hash record
                self.push_to_db()
                self.approval = 'IN_DATABASE'
                self.add_comment('[auto] moved to database')
            else:
                self.approval = 'INVALID'
                self.add_comment('[auto] no entry to move to database')

    def save(self, *args, **kwargs):
        self.pre_save_hook()
        ValidatedDocument.save(self, *args, **kwargs)

    def delete(self, *args, **kwargs):
        self.remove_source_file(True, True)
        ValidatedDocument.delete(self, *args, **kwargs)


class Plugin(Document):
    """
    A key value store for plugins
    """
    meta = {'collection': 'plugins'}

    plugin = StringField(primary_key=True)
    config = DictField()

    def set(self, key, value):
        self.config[key] = value
        self.save()

    def pop(self, key):
        self.config.pop(key)
        self.save()

    def get(self, key):
        return self.config.get(key, None)


# All the models in the event something would like to grab them all
MODELS = [Hash, Account, Submission]
