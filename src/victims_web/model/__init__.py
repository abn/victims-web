import json

from datetime import datetime
from flask.mongoengine import Document
from mongoengine import StringField, DateTimeField, ObjectIdField


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

        :rtype: string
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

    @property
    def json(self):
        return self.jsonify()

    @property
    def mongo(self):
        return self.mongify()


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
    created = DateTimeField(default=datetime.utcnow)
    modified = DateTimeField(default=datetime.utcnow)

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
            self.modified = datetime.utcnow()
            self.on_update()
        super(UpdateableDocument, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        A delete wrapper that creates a new Removal document once deletion
        succeeds.
        """
        super(UpdateableDocument, self).delete(*args, **kwargs)
        # post deletion, add a delete entry

        # backwards compat
        hash = None
        if hasattr(self, 'checksums') and 'sha512' in self.checksums:
            hash = self.checksums['sha512']

        Removal(
            oid=self.id,
            group=self.group,
            collection=self._meta['collection'],
            hash=hash
        ).save()
        self.on_delete()


class Removal(UpdateableDocument):

    """
    A removal document maintains history on all UpdateableDocument's that were
    deleted.
    """
    meta = {'collection': 'removals'}

    # backwards compat for v2
    hash = StringField(default=None)

    oid = ObjectIdField()
    group = StringField()
    collection = StringField()
