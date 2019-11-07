import json
import http.client
import sys
from urllib.parse import urlparse

from virgil_keymanager.consts import CLOUD_KEY_INIT_ENDPOINT, CLOUD_KEY_RECEIVE_ENDPOINT


def init_cloud_key(context, logger, ui):
    """
    Init procedure should be done for each application -
    that`s when Cloud key is generated on service.
    """
    conn = http.client.HTTPSConnection(host=urlparse(context.virgil_api_url).netloc)
    conn.request(method="POST",
                 url=CLOUD_KEY_INIT_ENDPOINT,
                 headers={"AppToken": context.application_token})
    response = conn.getresponse()
    resp_body = response.read().decode()
    if response.status not in (200, 400):  # 400 - cloud key was already initialized
        err_msg = ("[ERROR]: Failed to initialize cloud key at {api_url}{ep}\n"
                   "Response status code: {status}\n"
                   "Response body: {body}".format(api_url=context.virgil_api_url,
                                                  ep=CLOUD_KEY_INIT_ENDPOINT,
                                                  status=response.status,
                                                  body=resp_body))
        ui.print_error(err_msg)
        logger.error(err_msg)
        sys.exit(1)
    ui.print_message("Cloud key initialized")
    logger.error("Cloud key initialized")


def receive_cloud_public_key(context, logger, ui):
    """
    Receive public key of Cloud key from service
    """
    conn = http.client.HTTPSConnection(host=urlparse(context.virgil_api_url).netloc)
    conn.request(method="GET",
                 url=CLOUD_KEY_RECEIVE_ENDPOINT,
                 headers={"AppToken": context.application_token})
    response = conn.getresponse()
    resp_body = response.read().decode()
    if response.status != 200:
        err_msg = ("[ERROR]: Failed to receive cloud key at {api_url}{ep}\n"
                   "Response status code: {status}\n"
                   "Response body: {body}".format(api_url=context.virgil_api_url,
                                                  ep=CLOUD_KEY_RECEIVE_ENDPOINT,
                                                  status=response.status,
                                                  body=resp_body))
        ui.print_error(err_msg)
        logger.error(err_msg)
        sys.exit(1)
    return json.loads(resp_body)
