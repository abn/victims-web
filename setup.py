#!/usr/bin/env python
#
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
Source build and installation script.
"""

from pip.req import parse_requirements
from setuptools import setup


def extract_requirements(filename):
    return [str(r.req) for r in parse_requirements(filename)]


install_requires = extract_requirements('requirements.txt')
test_require = extract_requirements('test-requirements.txt')


setup(
    name='victims_web',
    version='2.1.0-dev',
    description='Victims Web Service',
    author='Steve Milner',
    url='https://victi.ms',
    license='GNU AGPLv3',

    package=['victims_web'],
    package_dir={'': 'src'},

    install_requires=install_requires,
    tests_require=test_require,
)
