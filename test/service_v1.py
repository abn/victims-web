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
Service version 1 testing.
"""

import json

from test import FlaskTestCase


class TestServiceV1(FlaskTestCase):

    """
    Tests for version 1 of the web service.
    """

    def test_status(self):
        """
        Verifies the status data is correct.
        """
        resp = self.app.get('/service/v1/status.json')
        assert resp.content_type == 'application/json'

        result = json.loads(resp.data)

        from datetime import datetime
        from victims_web.blueprints.service.v1 import EOL

        assert result['version'] == '1'
        assert result['recommended'] is False
        assert result['eol'] == EOL.isoformat()
        assert result['supported'] == (datetime.now() <= EOL)
        assert result['endpoint'] == '/service/v1/'
