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
Version 3 of the webservice. Remember service versions are not the same as
application versions.
"""
from flask import Blueprint, Response

from victims_web.handlers.updates import BEGINNING_OF_TIME, UpdateStream


bp = Blueprint('service.v3', __name__)

# Module globals
EOL = None
MIME_TYPE = 'application/json'


def make_response(data, code=200):
    return Response(
        response=data,
        status=code,
        mimetype=MIME_TYPE
    )


def format_document(doc, action, since):
    return '{%s: %s, "action": %s)' % (
        doc._meta['collection'], doc.to_json(), action)


@bp.route('/updates/<group>/', defaults={'since': None})
@bp.route('/updates/<group>/<since>')
def updates(group, since):
    if since is None:
        since = BEGINNING_OF_TIME
    stream = UpdateStream(group, since)
    resp = ''
    for s, a in stream:
        resp += format_document(s, a, since)
    return resp
