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
Version 2 of the webservice. Remember service versions are not the same as
application versions.
"""
from datetime import datetime
from flask import Blueprint, request, current_app

from victims_web.cache import cache
from victims_web.config import DEFAULT_GROUP
from victims_web.handlers.query import StreamedQuerySet
from victims_web.handlers.security import apiauth, api_request_user
from victims_web.handlers.sslify import ssl_exclude
from victims_web.model import Removal
from victims_web.model.evd import Artifact, Record
from victims_web.submissions import submit, upload
from victims_web.util import groups, group_keys, request_coordinates


from victims_web.handlers.routes import RouteRegex as Regex, maketime
from victims_web.handlers.updates import BEGINNING_OF_TIME, UpdateStream
from victims_web.blueprints.service.response import (
    StreamedQueryResponse, ServiceResponseFactory, StreamedSerialResponseValue)


EOL = datetime(2014, 6, 1)
bp = Blueprint('service.v2', __name__)


class UpdateStreamV2(UpdateStream):
    MODELS = [Record]


class RemoveStreamV2(UpdateStream):
    MODELS = [Removal]


def format_remove(doc):
    if doc.hash is None:
        return ''
    return {
        'fields': {
            'date': doc.created,
            'hash': doc.hash or '',
        }
    }


def format_update(doc):
    return {
        'fields': {
            'name': doc.filename or '',
            'date': doc.modified,
            'hash': doc.artifact.checksums['sha512'],
            'hashes': {
                'sha512': {
                    'files': doc.artifact.fingerprint.files,
                    'combined': doc.artifact.checksums['sha512']
                }
            },
            'cves': doc.cves,
            'meta': [{
                'properties': doc.coordinates,
                'filename': 'victims.submission'
            }],
            'status': 'RELEASED',
            'vendor': 'UNKNOWN',
        }
    }


class StreamedQueryResponseV2(StreamedQueryResponse):

    def format_update_item(self, item):
        doc = item.document
        if isinstance(doc, Removal):
            item = format_remove(doc)
        elif isinstance(doc, Record):
            item = format_update(doc)
        else:
            item = super(
                StreamedQueryResponseV2, self).format_update_item(item)
        return self.jasonize(item)


class StreamedSerialResponseValueV2(StreamedSerialResponseValue):

    def __iter__(self):
        for item in self.sqr:
            yield item


class ServiceResponseFactoryV2(ServiceResponseFactory):

    def format_data(self, data):
        return data

    def create_stream(self, data):
        return StreamedSerialResponseValueV2(data, StreamedQueryResponseV2)


factory = ServiceResponseFactoryV2(2, EOL, True, False)


@bp.route('/', defaults={'path': ''})
@bp.route('/<path:path>/')
def invalid_call(path):
    return factory.error('Invalid API call', 404, path=path)


@bp.route('/update/%s/' % (Regex.SINCE), defaults={'group': DEFAULT_GROUP})
@bp.route('/update/%s/' % (Regex.GROUP), defaults={'since': BEGINNING_OF_TIME})
@bp.route('/update/%s/%s/' % (Regex.GROUP, Regex.SINCE), methods=['GET'])
def update(group, since):
    if isinstance(since, str) or isinstance(since, unicode):
        since = maketime(since)
    return factory.make_response(UpdateStreamV2(group, since, False))


@bp.route('/remove/%s/' % (Regex.SINCE), defaults={'group': DEFAULT_GROUP})
@bp.route('/remove/%s/%s/' % (Regex.GROUP, Regex.SINCE))
def remove(group, since):
    if isinstance(since, str) or isinstance(since, unicode):
        since = maketime(since)
    return factory.make_response(RemoveStreamV2(group, since, False))


@bp.route('/status/')
@bp.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    return factory.status()


@bp.route('/cves/<algorithm>/<arg>/', methods=['GET'])
def cves_algorithm(algorithm, arg):
    """
    Returns any cves that match the given the request.

    If GET, we check only the combined hashes for the given algorithm for
    matches.

    :Parameters:
       - `algorithm`: Fingerprinting algorithm.
       - `arg`: The fingerprint.
    """
    try:
        algorithms = ['sha512', 'sha1', 'md5']
        if algorithm not in algorithms:
            return factory.error(
                'Invalid alogrithm. Use any of %s.' % (', '.join(algorithms)))
        elif len(arg) not in [32, 40, 128]:
            return factory.error(
                'Invalid checksum length for %s' % (algorithm))

        # this lookup is a hack since artifacts__in based querying does not
        # work as expected with reference fields
        kwargs = {("checksums__%s" % (algorithm)): arg}
        artifacts = [a.id for a in Artifact.objects(**kwargs).only('id')]
        records = []
        for record in Record.objects.no_dereference().only('cves', 'artifact'):
            if record.artifact.id in artifacts:
                records.append({'cves': record.cves})
        return factory.make_response(records)
    except Exception:
        return factory.error()


@bp.route('/cves/<group>/', methods=['GET'])
def cves(group):
    """
    Get cves that match the given coordinates for the specified group.

    Expectes coordinates as arguments.

    :Parameters:
        - `group`: The group for which to search in
    """
    try:
        kwargs = {
            'coordinates__%s' % (c): v
            for c, v in request_coordinates(group).items()
        }

        if len(kwargs) == 0:
            raise ValueError('No coordinates given')

        kwargs['group'] = group
        fields = ['cves', 'coordinates']
        records = Record.objects.only(*fields).filter(**kwargs)
        return factory.make_response(StreamedQuerySet(records))
    except ValueError as ve:
        return factory.error(ve.message)
    except Exception as e:
        current_app.logger.debug(e.message)
        return factory.error()


@bp.route('/submit/hash/<group>/', methods=['PUT'])
@apiauth
def submit_hash(group):
    """
    Allows for authenticated users to submit hashes via json.
    """
    user = '%s' % api_request_user()
    try:
        if group not in groups():
            raise ValueError('Invalid group specified')
        json_data = request.get_json()
        if 'cves' not in json_data:
            raise ValueError('No CVE provided')

        hashes = json_data.get(
            'hashes', {}).get('sha512', {}).get('files', None)
        coordinates = json_data.get('coordinates', {})
        submit(
            submitter=user, source='json-api-hash', group=group, hashes=hashes,
            cves=json_data['cves'], approval='PENDING_APPROVAL',
            coordinates=coordinates)
        return factory.success()
    except ValueError as ve:
        return factory.error(ve.message)
    except Exception as e:
        current_app.logger.info('Invalid submission by %s' % (user))
        current_app.logger.debug(e)
        return factory.error()


@bp.route('/submit/archive/<group>/', methods=['PUT'])
@apiauth
def submit_archive(group):
    """
    Allows for authenticated users to submit archives
    """
    user = '%s' % api_request_user()
    try:
        if group not in groups():
            raise ValueError('Invalid group specified')

        if 'cves' not in request.args:
            raise ValueError('CVE(s) required')

        cves = [cve.strip() for cve in request.args['cves'].split(',')]

        coordinates = {
            coord: request.args.get(coord).strip()
            for coord in group_keys(group)
            if coord in request.args
        }
        files = upload(group, request.files.get('archive', None), coordinates)

        for (ondisk, filename, suffix) in files:
            submit(
                submitter=user, source=ondisk, group=group, filename=filename,
                cves=cves, coordinates=coordinates
            )

        return factory.success()
    except ValueError as ve:
        current_app.logger.info('Invalid submission by %s: %s' %
                                (user, ve.message))
        return factory.error(ve.message)
    except Exception as e:
        current_app.logger.info(e.message)
        return factory.error()

SUBMISSION_ROUTES = [submit_hash, submit_archive]

for v in [update, remove, cves]:
    ssl_exclude(update)
