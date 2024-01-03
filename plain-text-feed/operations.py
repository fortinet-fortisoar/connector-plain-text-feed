"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import re

from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError


logger = get_logger("plain-text-feed")


class PlainTextFeed:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url")
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        self.url = server_url
        self.verify_ssl = config.get("verify_ssl")

    def api_request(self, method="GET"):
        try:
            response = request(method, self.url, verify=self.verify_ssl)

            if response.status_code in [200, 201, 204]:
                return response.text
            else:
                if response.text != "":
                    err_resp = response.text
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, err_resp)
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.content)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def extract_ips(text):
    # Regular expression pattern for both IPv4 and IPv6 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
    # Find all matches in the text
    matches = ip_pattern.findall(text)
    return matches


def get_indicators(config, params):
    ob = PlainTextFeed(config)
    res = ob.api_request()
    text_data = res.split("\n")
    data_list = []
    for text_line in text_data:
        data_list.extend(extract_ips(text_line))
    return data_list


def check_health_ex(config):
    get_indicators(config, {})
    return True


operations = {
    "get_indicators": get_indicators,
}
