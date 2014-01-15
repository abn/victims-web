
from flask.mongoengine import Document
from mongoengine import StringField, DictField


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
