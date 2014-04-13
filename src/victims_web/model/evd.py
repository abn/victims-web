from datetime import datetime
from hashlib import sha512
from os import remove
from os.path import isfile

from mongoengine import StringField, DictField, MapField, ReferenceField, \
    ListField, DateTimeField, EmbeddedDocument, EmbeddedDocumentField

from victims_web.model import Choices, ValidatedDocument, JsonMixin, \
    UpdateMixin, StageableMixin
from victims_web.model.user import User, UserRoles


class Fingerprint(ValidatedDocument, JsonMixin, UpdateMixin, StageableMixin):

    """
    A document to contain an artifact's Victims fingerprtint.
    """
    meta = {
        'collection': 'fingerprints'
    }

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
    cves = ListField(required=True)
    filename = StringField(default=None)


class Record(ValidatedDocument, JsonMixin, UpdateMixin, BaseRecord):

    """
    A record document is the meta container holding CVE, coordinate and other
    information pertaining to an approved submission.
    """
    meta = {'collection': 'records'}

    artifact = ReferenceField(Artifact)


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
    submitter = StringField(default=None)  # ReferenceField(User)
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
        self.save()


class Submission(ValidatedDocument, BaseSubmission):

    """
    Submission records
    """
    meta = {'collection': 'submissions'}

    record = ReferenceField(Record)


class StagedSubmission(ValidatedDocument, BaseArtifact, BaseSubmission):

    """
    Staging collection for user submissions
    """
    meta = {'collection': 'staged_submission'}

    source = StringField()
    fingerprint = Fingerprint().stage(persist=False)

    @property
    def ready(self):
        if self.fingerprint.empty:
            return False
        if (not self.group or len(self.group.strip()) == 0):
            self.add_comment('no group specified')
            return False
        if len(self.cves) == 0:
            self.add_comment('no cves provided')
            return False
        if len(self.checksums) == 0:
            self.add_comment('no checksums provided')
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

    def _push(self):
        self.fingerprint.unstage()
        record = Record()
        record.artifact = Artifact(
            group=self.group,
            cves=self.cves,
            coordinates=self.coordinates,
            filename=self.filename,
            checksums=self.checksums,
            fingerprint=self.fingerprint.to_dbref()
        )
        record.save()
        if isfile(self.source):
            try:
                remove(self.source)
                self.comment('Source file deleted')
            except:
                self.comment(
                    'Source deletion failed: {0:s}'.format(self.source))
        Submission(
            submitter=self.submitter,
            comment=self.comment,
            approval=SubmissionState.IN_DATABASE,
            record=record.to_dbref()
        ).save()
        self.delete()

    def save(self, *args, **kwargs):
        if self.approval == SubmissionState.APPROVED or self.allow_auto_push:
            if self.ready:
                # cannot autopush approved submission
                self.approval = SubmissionState.INVALID
                return None
            self._push()
        else:
            super(StagedSubmission, self).save(*args, **kwargs)
