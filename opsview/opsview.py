#!/usr/bin/python
# coding: utf-8


from __future__ import unicode_literals
from __future__ import absolute_import
from __future__ import print_function
from getpass import getpass
from pprint import pformat
from functools import partial
import argparse
import datetime
import json
import logging
import requests


CACHE_VALIDITY = 15  # for how long cache should be active (minutes)
TOKEN_TIMEOUT = 15  # for how long a session token should be considered active

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class OpsviewApiException(Exception):
    pass

def login_required(f):
    '''
    Definition decorator for all function requiring an active session
    Credit: http://stackoverflow.com/a/7590709
    '''
    def _wrapper(self, *args, **kwargs):
        '''
        Function to be applied on top of all decorated methods
        '''
        if self._token_age:
            timediff = self._token_age - datetime.datetime.now()
            if timediff.total_seconds() / 60 > TOKEN_TIMEOUT:
                self.logout()  # Log out to invalidate previous token
                self.login()  # Request new token
        else:  # haven't logged in yet
            self.login()
        return f(self, *args, **kwargs)
    return _wrapper


class Opsview(object):
    '''
    TODO
    '''
    def __init__(self, host, port=443, use_ssl=True, verify_ssl=True,
                 username=None, password=None, token=None, use_cache=True,
                 verbose=False):
        self.host = host
        self.port = port
        self.ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.username = username
        self.password = password
        self._token_age = datetime.datetime.now() if token else None
        self.rest_url = 'http{}://{}:{}/rest'.format(
            's' if use_ssl else '',
            self.host,
            self.port
        )
        self.headers = {
            'X-Opsview-Username': self.username,
            'X-Opsview-Token': token,
            'content-type': 'application/json'
        }
        # self.password = None
        self.__cache_hosts = None
        self.__cache_hosts_time = None
        self.__cache_host_templates = None
        self.__cache_hosts_templates_time = None
        self.use_cache = use_cache

    def api_version(self, verbose=False):
        '''
        Get information about the API
        http://docs.opsview.com/doku.php?id=opsview4.6:restapi#api_version_information
        '''
        return self.__auth_req_get(self.rest_url, verbose=verbose)

    @login_required
    def opsview_info(self, verbose=False):
        '''
        Get information about the current opsview instance
        http://docs.opsview.com/doku.php?id=opsview4.6:restapi#opsview_information
        '''
        url = '{}/{}'.format(self.rest_url, 'info')
        return self.__auth_req_get(url, verbose=verbose)

    def login(self, verbose=False):
        '''
        Authenticate with Opsview
        :param verbose: Verbose output mode
        :type verbose: bool
        :return: The authentification token
        :rtype: str or unicode
        '''
        url = '{}/{}'.format(self.rest_url, 'login')
        logger.debug('POST: {}'.format(url))
        r = requests.post(url, json={
                'username': self.username,
                'password': self.password
            },
            verify=self.verify_ssl
        )
        j = r.json()
        logger.debug('Request response:')
        logger.debug(pformat(vars(r)))
        logger.debug('JSON:')
        logger.debug(pformat(j))
        assert 'token' in j, 'Failed to retrieve token'
        self.headers['X-Opsview-Token'] = j['token']
        self._token_age = datetime.datetime.now()
        return j['token']

    @login_required
    def logout(self, verbose=False):
        '''
        Delete the current session
        http://docs.opsview.com/doku.php?id=opsview4.6:restapi#logout
        '''
        url = '{}/{}'.format(self.rest_url, 'logout')
        response = self.__auth_req_post(url, verbose=verbose)
        self.headers['X-Opsview-Token'] = None
        return response

    @login_required
    def user_info(self, verbose=False):
        '''
        Get information about the currently authenticated user
        http://docs.opsview.com/doku.php?id=opsview4.6:restapi#user_information
        '''
        url = '{}/{}'.format(self.rest_url, 'user')
        return self.__auth_req_get(url, verbose=verbose)

    @login_required
    def server_info(self, verbose=False):
        '''
        Get information about the Opsview monitoring servers
        http://docs.opsview.com/doku.php?id=opsview4.6:restapi#server_information
        '''
        url = '{}/{}'.format(self.rest_url, 'serverinfo')
        return self.__auth_req_get(url, verbose=verbose)

    @login_required
    def get_by_ref(self, ref, verbose=False):
        url = '{}/{}'.format(self.rest_url, ref.replace('/rest/', ''))
        return self.__auth_req_get(url, verbose=verbose)['object']

    @login_required
    def get_all_critical_alerts(self, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'status/host')
        return self.__auth_req_get(url, {'state': 2}, verbose)

    @login_required
    def get_all_alerts(self, verbose=False):
        params = {
            'state': [1, 2, 3], # warning, critical, unknown
            # 'hosts_state_type': 1,  # hard
        }
        f = partial(
            self.get, path='status/service', params=params, verbose=verbose
        )
        return self.paginated_fetch(f, verbose=verbose)

    @login_required
    def get_all_keywords(self, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/keyword')
        params = {'rows': 'all'}
        response = self.__auth_req_get(url, params, verbose=verbose)
        return [x['name'] for x in response['list']]

    @login_required
    def fetch_hosts(self, page=1, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/host')
        params = {'page': page}
        # Omit the page attr if the first one is requested. Otherwise we won't
        # be able to retrieve the total number of pages
        return self.__auth_req_get(
            url,
            params if page != 1 else None,
            verbose=verbose
        )

    @login_required
    def get_all_hosts(self, verbose=False):
        now = datetime.datetime.now()
        if self.use_cache:
            if not self.__cache_hosts_time:
                self.__cache_hosts_time = datetime.datetime.fromtimestamp(0)
            time_diff = now - self.__cache_hosts_time
            if (self.__cache_hosts_time and
                time_diff < datetime.timedelta(minutes=CACHE_VALIDITY)):
                return self.__cache_hosts
        f = partial(self.get, path='config/host', verbose=verbose)
        self.__cache_hosts = self.paginated_fetch(f, verbose=verbose)
        self.__cache_hosts_time = now
        return self.__cache_hosts

    @login_required
    def get_all_host_groups(self, verbose=False):
        f = partial(self.get, path='config/hostgroup', verbose=verbose)
        return self.paginated_fetch(f, verbose=verbose)

    @login_required
    def get_host_group_by_name(self, name, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/hostgroup')
        params = {'json_filter': json.dumps({'name': str(name)})}
        return self.__auth_req_get(url, params, verbose=verbose)['list'][0]

    @login_required
    def get_hosts_in_group(self, group, recursive=False, verbose=False):
        if type(group) is str or type(group) is unicode:
            group = self.get_host_group_by_name(group)
        hosts = []
        hosts += group['hosts']
        if recursive:
            for child in group['children']:
                hosts += self.get_hosts_in_group(child['name'], True, verbose)
        return hosts

    @login_required
    def get_all_host_templates(self, verbose=False):
        now = datetime.datetime.now()
        if self.use_cache:
            time_diff = now - self.__cache_host_templates_time
            if (self.__cache_host_templates_time and
                time_diff < datetime.timedelta(minutes=CACHE_VALIDITY)):
                return self.__cache_host_templates
        url = '{}/{}'.format(self.rest_url, 'config/hosttemplate')
        self.__cache_hosts = self.__auth_req_get(url, verbose=verbose)
        self.__cache_host_templates_time = now
        return self.__cache_host_templates

    @login_required
    def create_keyword(self, params=None, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/keyword')
        return self.__auth_req_post(url, params, verbose=verbose)

    @login_required
    def keyword_exists(self, keyword, verbose=False):
        keywords = self.get_all_keywords(verbose=verbose)
        return keyword in keywords

    @login_required
    def get_keyword(self, keyword, verbose=False):
        url = '{}/{}/{}'.format(self.rest_url, 'config/keyword', keyword)
        return self.__auth_req_get(url, verbose=verbose)

    @login_required
    def get_keyword_by_name(self, name, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/keyword')
        params = {'json_filter': json.dumps({'name': str(name)})}
        response = self.__auth_req_get(url, params, verbose=verbose)
        return response['list'][0]

    @login_required
    def create_host(self, params=None, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/host')
        return self.__auth_req_post(url, params, verbose=verbose)

    # @login_required
    # def create_host_from_template(self, hostname, template, verbose=False):
    #     url = '{}/{}'.format(self.rest_url, 'config/host')
    #     return self.__auth_req_post(url, params, verbose=verbose)

    @login_required
    def delete_host(self, host, verbose=False):
        if verbose:
            logger.info('Delete host {}'.format(host['name']))
        url = '{}/{}/{}'.format(self.rest_url, 'config/host', host['id'])
        return self.__auth_req_delete(url, verbose=verbose)

    @login_required
    def delete_hosts(self, hosts, verbose=False):
        response = []
        for h in hosts:
            response.append(self.delete_host(h, verbose))
        return response

    @login_required
    def get_hosts_by_keyword(self, keyword, verbose=False):
        # url = '{}/{}'.format(self.rest_url, 'config/host')
        # params = {'json_filter': json.dumps({'keywords': '/rest/config/keyword/' + str(keyword)})}
        # return self.__auth_req_get(url, params, verbose)
        matching_hosts = []
        hosts = self.get_all_hosts(verbose)
        for h in hosts: #['list']:
            for k in h['keywords']:
                if k['name'] == str(keyword):
                    matching_hosts.append(h)
        return matching_hosts

    @login_required
    def get_host_by_name(self, name, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/host')
        params = {'json_filter': json.dumps({'name': str(name)})}
        response = self.__auth_req_get(url, params, verbose=verbose)['list']
        if len(response) > 0:
            return response[0]

    @login_required
    def get_host_by_ip(self, ip, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/host')
        params = {'json_filter': json.dumps({'ip': str(ip)})}
        response = self.__auth_req_get(url, params, verbose=verbose)['list']
        if len(response) > 0:
            return response[0]

    @login_required
    def update_host(self, host, verbose=False):
        url = '{}/{}/{}'.format(self.rest_url, 'config/host', host['id'])
        return self.__auth_req_put(
            url, params=host, verbose=verbose
        )

    @login_required
    def get_host_template_by_name(self, name, verbose=False):
        url = '{}/{}'.format(self.rest_url, 'config/hosttemplate')
        params = {'json_filter': json.dumps({'name': str(name)})}
        return self.__auth_req_get(url, params, verbose=verbose)

    @login_required
    def get_monitoring_servers(self, verbose=False):
        f = partial(self.get, path='config/monitoringserver', verbose=verbose)
        return self.paginated_fetch(f, verbose=verbose)

    @login_required
    def reload_config(self, async=True, verbose=False):
        '''
        Initiate a config reload. This may take a while on large installations.
        '''
        url = '{}/{}{}'.format(
            self.rest_url, 'reload', '?asynchronous=1' if async else ''
        )
        return self.__auth_req_post(url, verbose=verbose)

    @login_required
    def paginated_fetch(self, func, verbose=False):
        # TODO Implement function wrapper that will implement pagination for
        # the decorated function
        r = func()
        results = r['list']
        # Return early if there is no page attribute in the response
        if 'page' not in r['summary']:
            return results
        page = int(r['summary']['page'])
        total_pages = int(r['summary']['totalpages'])
        total_rows = int(r['summary']['allrows'])
        while page < total_pages:
            page += 1
            logger.debug('Fetch page {}/{}'.format(page, total_pages))
            results += func(page=page)['list']
        if len(results) != total_rows:
            logger.warning(
                '{} results were retrieved but the API server explicitely stated '
                'that there were {}'.format(len(results), total_rows)
            )
        return results

    def get(self, path, page=1, params=None, verbose=False):
        url = '{}/{}'.format(self.rest_url, path)
        # Omit the page attr if the first one is requested. Otherwise we won't
        # be able to retrieve the total number of pages
        if params:
            if page != 1:
                params['page'] = page
        else:
            if page != 1:
                params = {'page': page}

        return self.__auth_req_get(
            url,
            params,
            verbose=verbose
        )


    def update_object(self, opsview_object, verbose=False):
        pass

    def __auth_req(self, method, url, params, verbose=False):
        logger.debug('{} {}'.format(method, url))
        logger.debug('HEADERS: {}'.format(self.headers))
        logger.debug('PARAMS: {}'.format(params))
        # If a GET call is requested, pass the parameters in the URL
        if method == 'GET':
            pargs = {'params': params}
        else:
            pargs = {'json': params}
        r = requests.request(
            method, url, headers=self.headers, verify=self.verify_ssl, **pargs
        )
        if not r.ok:
            logger.debug(r.content)
            r.raise_for_status()
        try:
            return r.json()
        except:
            logger.warning('JSON DECODE FAILED')
            logger.debug(r.content)


    def __auth_req_get(self, url, params=None, verbose=False):
        return self.__auth_req('GET', url, params, verbose)

    def __auth_req_post(self, url, params=None, verbose=False):
        return self.__auth_req('POST', url, params, verbose)

    def __auth_req_put(self, url, params=None, verbose=False):
        return self.__auth_req('PUT', url, params, verbose)

    def __auth_req_delete(self, url, params=None, verbose=False):
        return self.__auth_req('DELETE', url, params, verbose)


def get_args():
    '''
    Parse CLI args
    '''
    parser = argparse.ArgumentParser(description='Process args')
    parser.Add_argument(
        '-H', '--host',
        required=True,
        action='store',
        help='Remote host to connect to'
    )
    parser.add_argument(
        '-P', '--port',
        type=int,
        default=443,
        action='store',
        help='Port to connect on'
    )
    parser.add_argument(
        '-u', '--user',
        required=True,
        action='store',
        help='User name to use when connecting to host'
    )
    parser.add_argument(
        '-p', '--password',
        required=False,
        action='store',
        help='Password to use when connecting to host'
    )
    parser.add_argument(
        '-s', '--ssl',
        required=False,
        action='store_true',
        help='Use SSL'
    )
    parser.add_argument(
        '-k', '--skip-ssl-verification',
        required=False,
        default=False,
        action='store_true',
        help='Skip SSL certificate validation'
    )
    parser.add_argument(
        '-n', '--dryrun',
        required=False,
        action='store_true',
        default=False,
        help='Dry run. Don\'t annotate any VM'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help='Verbose output'
    )
    return parser.parse_args()


def main():
    '''
    Main function
    '''
    args = get_args()
    if args.password:
        password = args.password
    else:
        password = getpass(
            prompt='Enter password for {}@{}: '.format(args.user, args.host)
        )
    opsview = Opsview(
        host=args.host,
        port=args.port,
        use_ssl=args.ssl,
        verify_ssl=not args.skip_ssl_verification,
        username=args.user,
        password=password,
        verbose=args.verbose,
    )
    d = {}
    with open('vcenter.json') as f:
        d = json.load(f)
    logger.debug(
        pformat(opsview.create_host(params=d, verbose=args.verbose))
    )


if __name__ == '__main__':
    main()
