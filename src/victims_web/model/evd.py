
from hashlib import sha512

from mongoengine import StringField, DictField, MapField, ReferenceField, \
    ListField

from victims_web.models import UpdateableDocument


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
