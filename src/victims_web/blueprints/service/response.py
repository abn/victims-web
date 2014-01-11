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

import json
from flask import Response
from victims_web.handlers.updates import UpdateStreamItem
from victims_web.handlers.query import DocumentStream, DocumentStreamItem


def handle_special_objs(obj):
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    return str(obj)


class StreamedQueryResponse(object):

    def __init__(self, stream):
        """
        Creates the streamed response iterator for an `UpdateStream`.

        :Parameters:
           - `result`: `DocumentStream` to stream.
        """
        self.stream = stream
        self.result_count = self.stream.count()

    def format_update_item(self, item):
        # c: collection, a: action, d: document
        response = '{"c": "%s", "a": "%s", "d": %s}'
        return response % (
            item.document._meta['collection'], item.action, item.document.json)

    def jasonize(self, item):
        """
        Get JSON representation for an item. This maybe me pre/post pickle.
        """
        if isinstance(item, str):
            return item
        elif isinstance(item, UpdateStreamItem):
            return self.format_update_item(item)
        elif isinstance(item, DocumentStreamItem):
            return item.document.json
        else:
            return json.dumps(item, default=handle_special_objs)

    def __getstate__(self):
        """
        The state returned is just the json string of the object
        """
        dump = [self.jasonize(o) for o in self.stream]
        return json.dumps((dump, self.result_count))

    def __setstate__(self, state):
        """
        When unpickling, convert the json string into an py-object
        """
        (self.stream, self.result_count) = json.loads(state)

    def __iter__(self):
        """
        The iterator implementing result to json string generator and
        splitting the results by newlines.
        """
        yield '['
        count = 0
        for item in self.stream:
            count += 1
            yield self.jasonize(item)
            if count != self.result_count:
                yield ","
        yield ']'


class StreamedSerialResponseValue(object):

    """
    A thin wrapper class around the cleaned/filtered results to enable
    streaming and caching simultaneously.
    """

    def __init__(self, stream, streamed_query_class=StreamedQueryResponse):
        self.sqr = streamed_query_class(stream)

    def __iter__(self):
        """
        The iterator implementing result to json string generator and
        splitting the results by newlines.
        """
        yield '{"data": '

        for item in self.sqr:
            yield item

        yield '}'


class ServiceResponseFactory(object):
    MIME_TYPE = 'application/json'

    def __init__(self, version, eol=None, supported=True, recommended=True):
        self._eol = eol
        self._version = version
        self._supported = supported
        self._recommended = recommended

    @property
    def eol(self):
        return self._eol

    @property
    def version(self):
        return self._version

    @property
    def recommended(self):
        return self._recommended

    @property
    def supported(self):
        return self._supported

    def format_data(self, data):
        return {'data': data}

    def create_stream(self, data):
        return StreamedSerialResponseValue(data)

    def make_response(self, data, code=200):
        if isinstance(data, DocumentStream):
            data = self.create_stream(data)
        elif isinstance(data, str):
            data = data
        else:
            data = json.dumps(
                self.format_data(data), default=handle_special_objs)

        return Response(
            response=data,
            status=code,
            mimetype=self.MIME_TYPE
        )

    def error(self, msg='Could not understand request.', code=400, **kwargs):
        """
        Returns an error json response.

        :Parameters:
            - `msg`: Error message to be returned in json string.
            - `code`: The code to return as status code for the response.
        """
        kwargs['error'] = msg
        return self.make_response(json.dumps(kwargs), code)

    def success(self, msg='Request successful.', code=201, **kwargs):
        """
        Returns a success json resposne.

        :Paramenters:
            - `msg`: Error message to be returned in json string.
            - `code`: The code to return as status code for the response.
        """
        kwargs['success'] = msg
        return self.make_response(json.dumps(kwargs), code)

    def status(self):
        """
        Returns the status for this service.
        """
        data = {}

        if self.eol is not None:
            data['eol'] = self.eol
        data['supported'] = self.supported
        data['recommended'] = self.recommended
        data['version'] = self.version
        data['format'] = self.MIME_TYPE
        data['endpoint'] = '/service/v%d/' % (self.version)

        return self.make_response(
            json.dumps(data, default=handle_special_objs))
