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
Victims handlers for database querying.
"""

from abc import ABCMeta, abstractmethod


class DocumentStream(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def count(self):
        pass

    @abstractmethod
    def next(self):
        pass

    @abstractmethod
    def __iter__(self):
        pass


class DocumentStreamItem(object):

    def __init__(self, doc):
        self._doc = doc

    @property
    def document(self):
        return self._doc


class StreamedQueryItem(DocumentStreamItem):
    pass


class StreamedQuerySet(DocumentStream):

    def __init__(self, query_set):
        self._qs = query_set

    def __getattr__(self, attr):
        return getattr(self._qs, attr)

    def count(self):
        return self._qs.count()

    def next(self):
        self._qs.next()

    def __iter__(self):
        for doc in self._qs:
            yield StreamedQueryItem(doc)


class LookAheadQuerySet(StreamedQuerySet):

    """
    A wrapper class for mongoengine `QuerySet` that allows adds a
    lookahead-like field.
    """

    def __init__(self, query_set):
        super(LookAheadQuerySet, self).__init__(query_set)
        self._lookahead = None

    @property
    def lookahead(self):
        if self._lookahead is None:
            try:
                self._lookahead = self._qs.next()
            except:
                return None
        return self._lookahead

    def next(self):
        """
        Overides the default next implementation.
        """
        nxt = self.lookahead
        self._lookahead = None
        return nxt
