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
Victims handler for routes.
"""
from datetime import datetime
from victims_web.config import SUBMISSION_GROUPS, VICTIMS_TIME_FMT


def maketime(string):
    return datetime.strptime(string, VICTIMS_TIME_FMT)


class RouteRegex(object):
    SINCE = '<regex("[0-9\-]{8,}T[0-9:]{8}"):since>'
    GROUP = '<regex("%s"):group>' % ('|'.join(SUBMISSION_GROUPS.keys()))
