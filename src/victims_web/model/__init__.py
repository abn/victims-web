import json

from copy import deepcopy
from datetime import datetime
from flask.ext.mongoengine import Document
from mongoengine import StringField, DateTimeField, ObjectIdField
from victims_web.util import groups


class Choices(object):

    def __init__(self, choices, default):
        self._choices = choices
        self._default = default

    @property
    def default(self):
        return self._default

    @property
    def choices(self):
        return self._choices.items()

    @property
    def dict(self):
        return self._choices

    def __getattr__(self, key):
        if key in self._choices:
            return key
        raise AttributeError('Invalid choice "{0:s}"'.format(key))


class ValidatedDocument(Document):

    """
    Extended MongoEngine document which can use custom validators.
    """
    meta = {
        'allow_inheritance': False,
        'abstract': True
    }

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

    def pre_save(self):
        """
        Actions to perform before saving. These actions are performed before
        any other actions prior to save.
        """
        pass

    def pre_delete(self):
        """
        Actions to perform before deleting.
        """
        pass

    def copy(self):
        """
        Return a deep copied instance of this Document.
        """
        return deepcopy(self)

    def save(self, *args, **kwargs):
        """
        Saves the document to the database.

        :Parameters:
           - `args`: All non-keyword args.
           - `kwargs`: All keyword args.
        """
        self.pre_save()

        if self.is_new:
            self.on_create()

        if self.is_dirty:
            self.on_update()

        super(ValidatedDocument, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        A delete wrapper that creates a new Removal document once deletion
        succeeds.
        """
        self.pre_delete()
        super(ValidatedDocument, self).delete(*args, **kwargs)
        self.on_delete()


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

    def jsonify(self, fields=None):
        """
        Get JSON string representation of this Document instance.

        :rtype: string
        """
        return json.dumps(self.mongify(), default=self._handle_special_objs)

    def mongify(self, raw=False, fields=None):
        """
        Return a json friendly filtered python dict

        :param raw: Return the raw `to_mongo` return value of the `Document`.
            Defaults to False.
        :param fields: Return only these fields
        :type raw: bool
        """
        if raw:
            return self.to_mongo()

        allowed = {}
        if fields is not None:
            for field in fields:
                fs = field.split('.', 1)
                f = fs[0]
                s = fs[1] if len(fs) > 1 else None
                allowed[f] = s

        result = {}
        for key in self._fields:
            if key not in self.json_skip and \
                    (fields is None or key in allowed):
                value = getattr(self, key)
                if isinstance(value, JsonMixin):
                    value = value.mongify(allowed.get(key, None))
                if value is not None:
                    result[key] = value
        return result

    @property
    def json(self):
        return self.jsonify()

    @property
    def mongo(self):
        return self.mongify()


class UpdateMixin(object):

    group = StringField(choices=groups())
    created = DateTimeField(default=datetime.utcnow)
    modified = DateTimeField(default=datetime.utcnow)

    @property
    def json_skip(self):
        return super(UpdateMixin, self).json_skip + [
            'group', 'created', 'modified'
        ]

    def on_update(self):
        # update modified timestamp
        self.modified = datetime.utcnow()
        super(UpdateMixin, self).on_update()

    def on_delete(self):
        # post deletion, add a delete entry
        # backwards compat
        hash = None
        if hasattr(self, 'checksums') and 'sha512' in self.checksums:
            hash = self.checksums['sha512']
        Removal(
            oid=self.id,
            group=self.group,
            collection=self._get_collection_name(),
            hash=hash
        ).save()
        super(UpdateMixin, self).on_delete()


class StageableMixin(object):

    @property
    def stage_prefix(self):
        return 'stage_'

    @property
    def original_collection(self):
        return self._get_collection_name()

    @property
    def collection(self):
        return self._get_collection().name

    def stage(self, persist=True):
        if not self.staged:
            if persist:
                self.delete()
            collection = '{0:s}{1:s}'.format(
                self.stage_prefix, self.collection)
            self.switch_collection(collection)
            if persist:
                self.save()
        return self

    def unstage(self, persist=True):
        if persist:
            self.delete()
        self.switch_collection(self.original_collection)
        if persist:
            self.save()
        return self

    @property
    def staged(self):
        return self.collection.startswith(self.stage_prefix)


class Removal(ValidatedDocument, JsonMixin, UpdateMixin):

    """
    A removal document maintains a record of all tracked documents  that were
    deleted.
    """
    meta = {'collection': 'removals'}

    # backwards compat for v2
    hash = StringField(default=None)

    oid = ObjectIdField()
    group = StringField()
    collection = StringField()
