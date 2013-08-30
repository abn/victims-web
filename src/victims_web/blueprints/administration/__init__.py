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
Administration interface.
"""

import datetime

from flask import flash, redirect, url_for

from flask.ext.admin.base import (
    Admin, AdminIndexView, MenuLink, BaseView, expose)
from flask.ext.admin.contrib.mongoengine import ModelView
from victims_web.models import Account, Hash, Submission
from victims_web.cache import cache

from flask.ext import login


class ViewRequiresAuthorization(object):
    """
    All admin views should mix this in.
    """

    def is_accessible(self):
        """
        The user must be authenticated and have the admin endorsement.
        """
        if login.current_user.is_authenticated():
            return login.current_user.is_admin()


class SafeAdminIndexView(ViewRequiresAuthorization, AdminIndexView):
    """
    Mixes in ViewRequiresAuthorization to require authorization.
    """
    pass


class SafeBaseView(ViewRequiresAuthorization, BaseView):
    """
    Mixes in ViewRequiresAuthorization to require authorization.
    """
    pass


class SafeModelView(ViewRequiresAuthorization, ModelView):
    """
    Mixes in ViewRequiresAuthorization to require authorization.
    """
    pass


class CacheAdminView(SafeBaseView):
    """
    Simple cache management.
    """

    @expose('/')
    def index(self):
        cached_info = {}
        err = False
        try:
            for key, value in cache.cache._cache.items():
                cached_info[key] = datetime.datetime.fromtimestamp(value[0])
        except:
            flash('Could not load cache!', category='info')
            err = True
        return self.render(
            'admin/cache_index.html', items=cached_info, err=err
        )

    @expose('/clear')
    def clear(self):
        try:
            cache.cache.clear()
        except:
            flash('Could not clear cache!', category='info')
        return redirect(url_for('.index'))


class AccountView(SafeModelView):
    column_filters = ('username', )
    column_exclude_list = ('password', 'apikey', 'secret')


class HashView(SafeModelView):
    column_filters = ('name', )
    column_list = ('name', 'version', 'format',
                   'status', 'submittedon', 'date')


class SubmissionView(SafeModelView):
    column_filters = ('submitter', 'submittedon', 'approval', )
    column_exclude_list = ('entry', 'source')


def administration_setup(app):
    """
    Hack to use the backend administration.
    """
    administration = Admin(
        name="Victims Admin", index_view=SafeAdminIndexView())
    administration.init_app(app)
    administration.add_view(AccountView(Account))
    administration.add_view(HashView(Hash))
    administration.add_view(SubmissionView(Submission))
    administration.add_view(CacheAdminView(name='Cache', endpoint='cache'))

    # Add links
    administration.add_link(MenuLink(name='Front End', endpoint='ui.index'))
    administration.add_link(MenuLink(
        name='Logout', endpoint='auth.logout_user'))

    return administration
