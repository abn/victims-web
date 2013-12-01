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


class LookAheadQuerySet():
    """
    A wrapper class for mongoengine `QuerySet` that allows adds a
    lookahead-like field.
    """
    def __init__(self, query_set):
        self._qs = query_set
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

    def __getattr__(self, attr):
        return getattr(self._qs, attr)