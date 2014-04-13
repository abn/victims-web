from urlparse import urlparse, urljoin
from flask import request, flash
from victims_web import config


def groups():
    """
    Retrieve a list of groups that we know of. All configured group names are
    returned.
    """
    return config.SUBMISSION_GROUPS.keys()


def group_keys(group):
    """
    Retrieve the metadata keys associated with a given group.
    """
    return config.SUBMISSION_GROUPS.get(group, [])


def safe_redirect_url():
    """
    Returns request.args['next'] if the url is safe, else returns none.
    """
    forward = request.args.get('next')
    if forward:
        host_url = urlparse(request.host_url)
        redirect_url = urlparse(urljoin(request.host_url, forward))
        if redirect_url.scheme in ('http', 'https') and \
                host_url.netloc == redirect_url.netloc:
            return forward
        else:
            flash('Invalid redirect requested.', category='info')
    return None


def request_coordinates(group):
    return {
        coord: request.args.get(coord).strip()
        for coord in group_keys(group)
        if coord in request.args
    }
