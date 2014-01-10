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
Version 1 of the webservice. Remember service versions are not the same as
application versions.
"""
from json import dumps
from flask import Blueprint, Response

from victims_web.cache import cache


EOL = '2013-06-01T00:00:00'
bp = Blueprint('service.v1', __name__)


def make_response(data, code=200):
    return Response(
        response=data,
        status=code,
        mimetype='application/json'
    )


@bp.route('/', defaults={'path': ''})
@bp.route('/<path:path>/')
def eol(path):
    """
    Backwards compatible placeholder response
    """
    response = [{'fields': {}, 'error': 'EOL'}]
    return make_response(dumps(response))


@bp.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    data = dumps({
        'eol': EOL,
        'supported': False,
        'version': '1',
        'recommended': False,
        'endpoint': '/service/v1/'
    })

    return make_response(data)
