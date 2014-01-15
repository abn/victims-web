from datetime import datetime
from hmac import HMAC
from hashlib import sha1
from os import urandom
from uuid import uuid4

from flask.ext.bcrypt import generate_password_hash
from mongoengine import StringField, EmailField, ListField, BooleanField, \
    DateTimeField

from victims_web.models import ValidatedDocument
from victims_web.config import BCRYPT_LOG_ROUNDS


def generate_client_secret(apikey):
    return HMAC(bytes(urandom(24)), apikey, sha1).hexdigest().upper()


def generate_apikey(username):
    apikey = HMAC(uuid4().hex, username).hexdigest()
    return apikey.upper()


def generate_api_tokens(username):
    apikey = generate_apikey(username)
    secret = generate_client_secret(apikey)
    return (apikey, secret)


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
    createdon = DateTimeField(default=datetime.utcnow)
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
