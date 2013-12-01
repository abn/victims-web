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
Victims handler for updates.
"""
from datetime import datetime
from victims_web.handlers.query import LookAheadQuerySet
from victims_web.models import \
    Record, Artifact, Fingerprint, Removal, UpdateableDocument


# The begining of time in the victims update universe
BEGINNING_OF_TIME = datetime.strptime(
    '1970-01-01T00:00:00', '%Y-%m-%dT%H:%M:%S')


class UpdateAction(object):
    """
    An enum emulator for Update Actions.
    """
    ADD = 'ADD'
    UPDATE = 'UPDATE'
    REMOVE = 'REMOVE'


class UpdateStream():
    """
    A combinator for multiple QuerySets of updatable models.
    """
    # Models to combine stream from
    MODELS = [Removal, Fingerprint, Artifact, Record]

    def __init__(self, group, since=BEGINNING_OF_TIME):
        self._streams = []
        self._since = since
        for Model in self.MODELS:
            if issubclass(Model, UpdateableDocument):
                self._streams.append(
                    LookAheadQuerySet(
                        Model.objects(
                            modified__gt=self.since,
                            group=group
                        ).order_by('created')
                    )
                )

    @property
    def since(self):
        return self._since

    @property
    def streams(self):
        return self._streams

    @property
    def active_streams(self):
        """
        Fetch all active streams in this instance. An active stream is a stream
        with documents remaining in the `QuerySet`.
        """
        active = []
        for stream in self.streams:
            if stream.lookahead is not None:
                active.append(stream)
        return active

    def action(self, doc):
        """
        Determine update action for a given document. The determination is made
        based on this UpdateStream's `since` field and the document's `created`
        and `modified` attributes.

        :param doc: Document for which the update action is to be identified
        :type doc: UpdateableDocument
        :rtype: string
        """
        if isinstance(doc, Removal):
            return UpdateAction.REMOVE
        elif doc.created == doc.modified or doc.created > self.since:
            return UpdateAction.ADD
        else:
            return UpdateAction.UPDATE

    def _stream_key(self, qs):
        """
        Smart key retrieval from a given `LookAheadQuerySet`. The created
        date is used if it is later than the stream's `since` attribute.

        :param qs: The LookAheadQuerySet to retrieve the key form
        :type qs: LookAheadQuerySet
        """
        if qs.lookahead.created > self.since:
            return qs.lookahead.created
        else:
            return qs.lookahead.modified

    def next(self):
        """
        Retrieve next document from stream.
        """
        active = self.active_streams

        count = len(active)
        if count == 0:
            return None
        elif count == 1:
            return active[0].next()
        else:
            return min(*active, key=self._stream_key).next()

    def __iter__(self):
        """
        Custom iterator that yeilds documents in update order with actions.
        """
        doc = self.next()
        while doc is not None:
            yield (doc, self.action(doc))
            doc = self.next()