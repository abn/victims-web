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
from flask import Blueprint

from victims_web.handlers.routes import RouteRegex as Regex, maketime
from victims_web.handlers.updates import BEGINNING_OF_TIME, UpdateStream
from victims_web.blueprints.service.response import ServiceResponseFactory

factory = ServiceResponseFactory(3, None)

bp = Blueprint('service.v3', __name__)


@bp.route('/', defaults={'path': ''})
@bp.route('/<path:path>/')
def invalid_call(path):
    return factory.error('Invalid API call', 404, path=path)


@bp.route('/update/%s/' % (Regex.GROUP), defaults={'since': BEGINNING_OF_TIME})
@bp.route('/update/%s/%s/' % (Regex.GROUP, Regex.SINCE), methods=['GET'])
def updates(group, since):
    if isinstance(since, str) or isinstance(since, unicode):
        since = maketime(since)
    return factory.make_response(UpdateStream(group, since))


@bp.route('/status/')
def status():
    return factory.status()
