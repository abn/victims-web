from datetime import datetime
from hashlib import sha512
from os import remove
from os.path import isfile

from mongoengine import StringField, DictField, MapField, ReferenceField, \
    ListField, DateTimeField, EmbeddedDocument, EmbeddedDocumentField

from victims_web.model import Choices, ValidatedDocument, JsonMixin, \
    UpdateMixin
from victims_web.model.user import User, UserRoles
from victims_web.util import group_keys


class Fingerprint(ValidatedDocument, JsonMixin, UpdateMixin, EmbeddedDocument):

    """
    A document to contain an artifact's Victims fingerprtint.
    """
    meta = {
        'collection': 'fingerprints'
    }

    uuid = StringField(default=None)
    files = DictField(default={})

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

    @property
    def empty(self):
        return len(self.files) == 0


class BaseArtifact(object):

    checksums = MapField(field=StringField())
    metadata = ListField(field=DictField())


class Artifact(ValidatedDocument, BaseArtifact, JsonMixin, UpdateMixin):

    """
    An artifact document contains artifact checksum in multiple algorithms and
    referes to a victims fingerprint document associated with the file.
    """
    meta = {'collection': 'artifacts'}

    fingerprint = ReferenceField(Fingerprint, default=None)


class BaseRecord(object):

    """
    BaseRecord
    """
    coordinates = DictField(default=None)
    cves = ListField(field=StringField(), required=True)
    filename = StringField(default=None)

    @property
    def coord(self):
        return ':'.join([
            self.coordinates.get(k, 'unknown')
            for k in group_keys(self.group)
        ])


class Record(ValidatedDocument, JsonMixin, UpdateMixin, BaseRecord):

    """
    A record document is the meta container holding CVE, coordinate and other
    information pertaining to an approved submission.
    """
    meta = {'collection': 'records'}

    artifact = ReferenceField(Artifact)

    @property
    def checksum(self):
        return self.artifact.checksums.get('sha512', None)


class Comment(EmbeddedDocument, JsonMixin):

    """
    Embedded Document to hold comment and metadata
    """
    date = DateTimeField(default=datetime.utcnow)
    message = StringField()
    author = StringField(default='auto')

    def __repr__(self):
        return '[{date:s}] [{author:s}] {message:s}'.format(
            date=self.date, author=self.author, message=self.message)

    def __str__(self):
        return self.__repr__()


SubmissionState = Choices(
    choices={
        'REQUESTED': 'REQUESTED',
        'PENDING_APPROVAL': 'PENDING APPROVAL',
        'APPROVED': 'APPROVED',
        'IN_DATABASE': 'IN DATABASE',
        'DECLINED': 'DECLINED',
        'INVALID': 'INVALID',
    }, default='REQUESTED')


class BaseSubmission(BaseRecord, JsonMixin, UpdateMixin):

    """
    Base class for submissions
    """
    submitter = StringField(default=None)
    comments = ListField(EmbeddedDocumentField(Comment), default=[])
    approval = StringField(
        choices=SubmissionState.choices,
        default=SubmissionState.default
    )

    @property
    def submittedon(self):
        return self.created

    @property
    def approved(self):
        return self.approval == SubmissionState.APPROVED

    @property
    def indb(self):
        return self.approval == SubmissionState.IN_DATABASE

    def comment(self, message, author='auto'):
        self.comments.append(Comment(message=message.strip(), author=author))
        ValidatedDocument.save(self)


class ApprovedSubmission(ValidatedDocument, BaseSubmission):

    """
    Submission records that were approved and moved to database
    """
    meta = {'collection': 'submissions'}

    record = ReferenceField(Record)


class Submission(ValidatedDocument, BaseArtifact, BaseSubmission):

    """
    Staging collection for user submissions
    """
    meta = {'collection': 'staged_submission'}

    source = StringField()
    fingerprint = EmbeddedDocumentField(Fingerprint)

    @property
    def ready(self):
        if self.fingerprint.empty:
            return False
        if (not self.group or len(self.group.strip()) == 0):
            self.comment('no group specified')
            return False
        if len(self.cves) == 0:
            self.comment('no cves provided')
            return False
        if len(self.checksums) == 0:
            self.comment('no checksums provided')
            return False
        return True

    @property
    def allow_auto_push(self):
        if self.approval in [
            SubmissionState.REQUESTED, SubmissionState.PENDING_APPROVAL] \
                and not self.ready and self.submitter is not None:
            user = User.objects(username=self.submitter).first()
            if user:
                if UserRoles.submitter in user.roles:
                    self.comment(
                        '{0:s} is a trusted submitter'.format(self.submitter))
                    return True
        return False

    def _remove_source(self):
        if isfile(self.source):
            try:
                remove(self.source)
                self.comment('Source file deleted')
            except:
                self.comment(
                    'Source deletion failed: {0:s}'.format(self.source))

    def _push(self):
        fingerprint = self.fingerprint.copy()
        fingerprint.save()
        record = Record()
        artifact = Artifact(
            group=self.group,
            coordinates=self.coordinates,
            filename=self.filename,
            checksums=self.checksums,
            fingerprint=fingerprint.to_dbref()
        )
        artifact.save()
        record.artifact = artifact.to_dbref()
        record.cves = self.cves
        record.save()
        ApprovedSubmission(
            cves=self.cves,
            submitter=self.submitter,
            comment=self.comment,
            approval=SubmissionState.IN_DATABASE,
            record=record.to_dbref()
        ).save()
        self.delete()
        self._remove_source()

    def save(self, *args, **kwargs):
        if self.approval == SubmissionState.APPROVED or self.allow_auto_push:
            if self.ready:
                # cannot autopush approved submission
                self.approval = SubmissionState.INVALID
                return None
            self._push()
        else:
            super(Submission, self).save(*args, **kwargs)
