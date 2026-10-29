# File: smtp_connector.py
#
# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import base64
import json
import mimetypes
import os
import re
import smtplib
import ssl
import sys
import time
from email import encoders, message_from_bytes, message_from_string
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.policy import SMTP

import bleach
import encryption_helper
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bleach.css_sanitizer import CSSSanitizer
from bleach_allowlist import all_styles, all_tags, generally_xss_unsafe
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# These public exports come from the compiled _pytidyhtml5 extension.
from pytidyhtml5 import OptionId, tidy_document  # pylint: disable=no-name-in-module

from request_handler import RequestStateHandler, _get_dir_name_from_app_name
from smtp_consts import *


class SmtpConnector(BaseConnector):
    # actions supported by this script
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_SEND_EMAIL = "send_email"
    ACTION_ID_SEND_RAW_EMAIL = "send_rawemail"
    ACTION_ID_SEND_HTML_EMAIL = "send_htmlemail"

    # Bleach/html5lib treats document wrapper tags as structural context for HTML
    # fragments and removes them from the sanitized output. Keep them allowed so
    # existing full-document email templates do not render the wrappers as text,
    # while unsupported tags are stripped when sanitization is enabled.
    SAFE_HTML_TAGS = list((set(all_tags) - set(generally_xss_unsafe)) | {"html", "head", "body"})

    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()
        self._smtp_conn = None
        self.invalid_vault_ids = list()
        self._access_token = None
        self._refresh_token = None
        self._auth_mechanism = None

    def initialize(self):
        # config = self.get_config()
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._reset_state()
            return self.set_status(phantom.APP_ERROR, SMTP_STATE_FILE_CORRUPT_ERROR)

        # action_result = self.add_action_result(ActionResult())

        # skipping the validation for email
        self.set_validator("email", lambda input: True)

        return phantom.APP_SUCCESS

    def _with_oauth_type(self, action_result):
        """Try to connect server with Interactive auth
        return : APP_SUCCESS/APP_ERROR
        """

        config = self.get_config()
        self._auth_mechanism = SMTP_OAUTH_AUTH_TYPE
        self.debug_print("Using Interactive Auth")
        required_params = ["username", "client_id", "client_secret", "auth_url", "token_url"]
        for key in required_params:
            if not config.get(key):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    SMTP_REQUIRED_PARAM_AUTH.format(self._auth_mechanism, self._auth_mechanism, ", ".join(i for i in required_params)),
                )

        self._access_token = self._state.get("oauth_token", {}).get("access_token")
        self._refresh_token = self._state.get("oauth_token", {}).get("refresh_token")

        if self._state.get(SMTP_STATE_IS_ENCRYPTED):
            try:
                if self._access_token:
                    self._access_token = self.decrypt_state(self._access_token, "access")
                if self._refresh_token:
                    self._refresh_token = self.decrypt_state(self._refresh_token, "refresh")
            except Exception as e:
                self.debug_print(f"{SMTP_DECRYPTION_ERROR}: {self._get_error_message_from_exception(e)}")
                return self.set_status(phantom.APP_ERROR, SMTP_DECRYPTION_ERROR)

        if phantom.is_fail(self._connect_to_server_helper(action_result)):
            self.debug_print("OAuth authentication failed")
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _with_basic_type(self, action_result):
        """Try to connect server with basic auth
        return : APP_SUCCESS/APP_ERROR
        """

        config = self.get_config()
        self._auth_mechanism = SMTP_BASIC_AUTH_TYPE

        self.debug_print("Using Basic Auth")
        required_params = ["username", "password"]
        for key in required_params:
            if not config.get(key):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    SMTP_REQUIRED_PARAM_AUTH.format(self._auth_mechanism, self._auth_mechanism, ", ".join(i for i in required_params)),
                )

        if phantom.is_fail(self._connect_to_server_helper(action_result)):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _with_passwordless_type(self, action_result):
        """Try to connect server with password less auth
        return : APP_SUCCESS/APP_ERROR
        """

        self._auth_mechanism = SMTP_PASSWORD_LESS_AUTH_TYPE
        self.debug_print("Using Passwordless")

        if phantom.is_fail(self._connect_to_server_helper(action_result)):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _process_auth_type(self, action_result):
        """Get auth from auth_type parameter and try to connect server with specified auth.
        return : APP_SUCCESS/APP_ERROR
        """

        config = self.get_config()
        action_id = " ".join(map(lambda x: x.title(), self.get_action_identifier().split("_")))

        self.debug_print("Determining auth type")
        auth_type = config.get("auth_type", SMTP_AUTOMATIC_AUTH_TYPE)
        auth_handlers = {
            SMTP_OAUTH_AUTH_TYPE: self._with_oauth_type,
            SMTP_BASIC_AUTH_TYPE: self._with_basic_type,
            SMTP_PASSWORD_LESS_AUTH_TYPE: self._with_passwordless_type,
        }

        # Check all the auth type as per inputs given by user with flow of [Interactive -> Basic -> Password less]
        self.save_progress(f"You have selected {auth_type} Authentication")  # nosemgrep
        if auth_type == SMTP_AUTOMATIC_AUTH_TYPE:
            for auth_type in SMTP_ALLOWED_AUTH_TYPES[1:]:
                self.save_progress(SMTP_AUTH_MESSAGE.format(auth_type))  # nosemgrep
                auth = auth_handlers[auth_type](action_result)
                if phantom.is_fail(auth):
                    msg = action_result.get_message()
                    self.save_progress(SMTP_AUTH_FAILED_ACTION_MESSAGE.format(action_id, auth_type, msg))  # nosemgrep
                    if auth_type == SMTP_PASSWORD_LESS_AUTH_TYPE:
                        if action_id != SMTP_TEST_CONNECTIVITY:
                            msg = f"Authentication failed for connecting to server with {SMTP_ALLOWED_AUTH_TYPES[1:]} types \
                            of authentication. Message: {msg}.{SMTP_FAILED_CONNECTIVITY_TEST}"
                            return action_result.set_status(phantom.APP_ERROR, msg)
                        return action_result.set_status(phantom.APP_ERROR)
                else:
                    return phantom.APP_SUCCESS

        # Check specific auth type as per input given by user in auth_type parameter
        auth_handler = auth_handlers.get(auth_type)
        if auth_handler is None:
            return action_result.set_status(phantom.APP_ERROR, f"Unsupported authentication type: {auth_type}")

        self.save_progress(SMTP_AUTH_MESSAGE.format(auth_type))  # nosemgrep
        auth = auth_handler(action_result)
        if phantom.is_fail(auth):
            self.debug_print(f"Authentication failed using {auth_type}")
            msg = action_result.get_message()
            if action_id != SMTP_TEST_CONNECTIVITY:
                msg = f"Authentication failed for connecting to server with {auth_type} authentication. Message: {msg}.{SMTP_FAILED_CONNECTIVITY_TEST}"
                return action_result.set_status(phantom.APP_ERROR, msg)
            return action_result.set_status(phantom.APP_ERROR, msg)

        self.debug_print(f"Authentication succeeded using {auth_type}")
        return phantom.APP_SUCCESS

    def finalize(self):
        if self._auth_mechanism == SMTP_OAUTH_AUTH_TYPE:
            try:
                if "oauth_token" in self._state:
                    if self._access_token:
                        self._state["oauth_token"]["access_token"] = self.encrypt_state(self._access_token, "access")
                    if self._refresh_token:
                        self._state["oauth_token"]["refresh_token"] = self.encrypt_state(self._refresh_token, "refresh")
                    else:
                        self._state["oauth_token"]["refresh_token"] = self._refresh_token
                    self._state[SMTP_STATE_IS_ENCRYPTED] = True
            except Exception as e:
                self.error_print(f"{SMTP_ENCRYPTION_ERROR}: {self._get_error_message_from_exception(e)}")
                return self.set_status(phantom.APP_ERROR, SMTP_ENCRYPTION_ERROR)

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _reset_state(self):
        self._state = {"app_version": self.get_app_json().get("app_version")}

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return phantom.APP_ERROR, SMTP_VALID_INT_MESSAGE.format(param=key)

                parameter = int(parameter)
            except Exception:
                return phantom.APP_ERROR, SMTP_VALID_INT_MESSAGE.format(param=key)

            if parameter < 0:
                return phantom.APP_ERROR, SMTP_NON_NEG_INT_MESSAGE.format(param=key)
            if not allow_zero and parameter == 0:
                return phantom.APP_ERROR, SMTP_NON_NEG_NON_ZERO_INT_MESSAGE.format(param=key)

        return phantom.APP_SUCCESS, parameter

    def make_rest_call(self, action_result, url, verify=False):
        try:
            r = requests.get(url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            if not r:
                message = f"Status Code: {r.status_code}"
                if r.text:
                    message = "{} Error from Server: {}".format(message, r.text.replace("{", "{{").replace("}", "}}"))
                return action_result.set_status(phantom.APP_ERROR, f"Error retrieving system info, {message}"), None
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error : {e}"), None

        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error processing response JSON", e), None

        return phantom.APP_SUCCESS, resp_json

    def _get_phantom_base_url_smtp(self, action_result):
        ret_val, resp_json = self.make_rest_call(action_result, f"{self.get_phantom_base_url()}rest/system_info")

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        phantom_base_url = resp_json.get("base_url")
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, "SOAR Base URL is not configured, please configure it in System Settings"), None

        phantom_base_url = phantom_base_url.strip("/")

        return phantom.APP_SUCCESS, phantom_base_url

    def _get_asset_name(self, action_result):
        ret_val, resp_json = self.make_rest_call(action_result, f"{self.get_phantom_base_url()}rest/asset/{self.get_asset_id()}")

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        asset_name = resp_json.get("name")
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving asset name"), None

        return phantom.APP_SUCCESS, asset_name

    def _get_url_to_app_rest(self, action_result=None):
        if not action_result:
            action_result = ActionResult()
        # get the phantom ip to redirect to
        ret_val, phantom_base_url = self._get_phantom_base_url_smtp(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), action_result.get_message()
        # get the asset name
        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), action_result.get_message()
        self.save_progress(f"Using SOAR base URL as: {phantom_base_url}")
        app_json = self.get_app_json()
        app_name = app_json["name"]
        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = "{}/rest/handler/{}_{}/{}".format(phantom_base_url, app_dir_name, app_json["appid"], asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _interactive_auth_initial(self, client_id, rsh, client_secret):
        state = rsh.load_state()
        asset_id = self.get_asset_id()

        ret_val, app_rest_url = self._get_url_to_app_rest()
        if phantom.is_fail(ret_val):
            return phantom.APP_ERROR, app_rest_url

        config = self.get_config()

        request_url = config.get("auth_url", "").strip("\\/")
        token_url = config.get("token_url", "").strip("\\/")
        # set proxy if configured
        proxy = {}
        if "HTTP_PROXY" in os.environ:
            proxy["http"] = os.environ.get("HTTP_PROXY")
        if "HTTPS_PROXY" in os.environ:
            proxy["https"] = os.environ.get("HTTPS_PROXY")
        if "NO_PROXY" in os.environ:
            proxy["no_proxy"] = os.environ.get("NO_PROXY")

        state["proxy"] = proxy

        state["client_id"] = client_id
        state["redirect_url"] = app_rest_url
        state["request_url"] = request_url
        state["token_url"] = token_url
        state["client_secret"] = base64.b64encode(client_secret.encode()).decode()

        rsh.save_state(state)
        self.save_progress(f"Redirect URI: {app_rest_url}")
        params = {"response_type": "code", "client_id": client_id, "state": asset_id, "redirect_uri": app_rest_url, "access_type": "offline"}

        if "gmail" in config[phantom.APP_JSON_SERVER]:
            params["prompt"] = "consent"

        if config.get("scopes"):
            params["scope"] = config["scopes"]

        try:
            url = requests.Request("GET", request_url, params=params).prepare().url
            url = f"{url}&"
        except Exception as e:
            return phantom.APP_ERROR, f"Message : {e}"

        self.save_progress("To continue, open this link in a new tab in your browser")
        self.save_progress(url)

        for i in range(0, 60):
            time.sleep(5)
            self.save_progress("." * i)

            # load_state also decrypts tokens, there if there is a error decrypting tokens raise an error
            try:
                state = rsh.load_state()
            except Exception:
                self._state.pop("oauth_token", None)
                return phantom.APP_ERROR, SMTP_ASSET_CORRUPTED

            oauth_token = state.get("oauth_token")
            if oauth_token:
                break
            elif state.get("error"):
                return phantom.APP_ERROR, "Error retrieving OAuth token"
        else:
            return phantom.APP_ERROR, "Timed out waiting for login"

        if oauth_token.get("access_token"):
            self._access_token = oauth_token.get("access_token")
        if oauth_token.get("refresh_token"):
            self._refresh_token = oauth_token.get("refresh_token")

        self._state["oauth_token"] = oauth_token

        return phantom.APP_SUCCESS, ""

    def _interactive_auth_refresh(self):
        self.debug_print("Attempting to refresh OAuth token")
        config = self.get_config()
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")

        oauth_token = self._state.get("oauth_token", {})
        if not self._refresh_token:
            self._reset_state()
            return phantom.APP_ERROR, "Unable to get refresh token. Please run Test Connectivity again."

        if client_id != self._state.get("client_id", ""):
            self._reset_state()
            return phantom.APP_ERROR, "Client ID has been changed. Please run Test Connectivity again."

        request_url = config.get("token_url")

        body = {"grant_type": "refresh_token", "client_id": client_id, "refresh_token": self._refresh_token, "client_secret": client_secret}

        try:
            r = requests.post(request_url, data=body, timeout=DEFAULT_REQUEST_TIMEOUT)
        except Exception as e:
            return phantom.APP_ERROR, f"Error refreshing token: {e!s}"

        try:
            response_json = r.json()
            if response_json.get("error"):
                self._reset_state()
                return phantom.APP_ERROR, "Invalid refresh token. Please run the test connectivity again."
            oauth_token.update(r.json())
        except Exception:
            return phantom.APP_ERROR, "Error retrieving OAuth Token"

        self._access_token = oauth_token.get("access_token")
        if response_json.get("refresh_token"):
            self.debug_print("Getting new refresh token.")
            self._refresh_token = oauth_token.get("refresh_token")

        self._state["oauth_token"] = oauth_token
        self.debug_print("OAuth token refresh succeeded")
        return phantom.APP_SUCCESS, ""

    def _set_interactive_auth(self, action_result):
        self.debug_print("Setting interactive auth")
        config = self.get_config()
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")

        # Run the initial authentication flow only if current action is test connectivity
        if self.get_action_identifier() != self.ACTION_ID_TEST_CONNECTIVITY:
            if not self._access_token:
                return phantom.APP_ERROR, "Unable to get access token. Has Test Connectivity been run?"

            try:
                ret_val = self._connect_to_server(action_result)
            except Exception as e:
                return self._parse_connection_error(action_result, e), action_result.get_message()

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, action_result.get_message()

        else:
            self.debug_print("Try to generate token from authorization code")
            asset_id = self.get_asset_id()
            rsh = RequestStateHandler(asset_id)  # Use the states from the OAuth login
            ret_val, message = self._interactive_auth_initial(client_id, rsh, client_secret)
            rsh.delete_state()

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, message

            self._state["client_id"] = client_id

            try:
                ret_val = self._connect_to_server(action_result)
            except Exception as e:
                return self._parse_connection_error(action_result, e), action_result.get_message()

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, action_result.get_message()

        return phantom.APP_SUCCESS, ""

    def encrypt_state(self, encrypt_var, token_name):
        """Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(SMTP_ENCRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.get_asset_id())

    def decrypt_state(self, decrypt_var, token_name):
        """Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(SMTP_DECRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.decrypt(decrypt_var, self.get_asset_id())

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_message = ERROR_MESSAGE_UNAVAILABLE
        self.error_print("Error occurred : ", e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.debug_print(f"Error occurred while fetching exception information. Details: {e!s}")

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    def _parse_connection_error(self, action_result, e):
        """An error has already occurred"""

        message = ""
        exception_message = ""

        try:
            config = self.get_config()
            exception_message = self._get_error_message_from_exception(e)
            port_message = " Please try without specifying the port. " if (config.get(SMTP_JSON_PORT)) else " "

            if (config[SMTP_JSON_SSL_CONFIG] == SSL_CONFIG_SSL) and ("ssl.c" in exception_message):
                message = (
                    f"{SMTP_ERROR_SMTP_CONNECTIVITY_TO_SERVER}.\r\n{SMTP_ERROR_SSL_CONFIG_SSL}{port_message}Error Text: {exception_message}"
                )
                return action_result.set_status(phantom.APP_ERROR, message)

            if (config[SMTP_JSON_SSL_CONFIG] == SSL_CONFIG_STARTTLS) and ("unexpectedly close" in exception_message):
                message = (
                    f"{SMTP_ERROR_SMTP_CONNECTIVITY_TO_SERVER}.\r\n{SMTP_ERROR_STARTTLS_CONFIG}{port_message}Error Text:{exception_message}"
                )
                return action_result.set_status(phantom.APP_ERROR, message)

        except Exception:
            pass

        return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_CONNECTIVITY_TO_SERVER}. {exception_message}")

    def _cleanup(self):
        if self._smtp_conn:
            self._smtp_conn.quit()
            self._smtp_conn = None

    def handle_exception(self, e):
        self._cleanup()

    def _connect_to_server(self, action_result, first_try=True):
        config = self.get_config()
        is_oauth = self._auth_mechanism == SMTP_OAUTH_AUTH_TYPE

        self._smtp_conn = None
        server = config[phantom.APP_JSON_SERVER]

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)

        # default the ssl config to non SSL i.e. either None or StartTLS
        func_to_use = getattr(smtplib, "SMTP")

        # Get the SSL config to use
        ssl_config = config.get(SMTP_JSON_SSL_CONFIG, SSL_CONFIG_STARTTLS)
        tls_context = ssl.create_default_context(cafile=self.get_ca_bundle())
        if not config.get(SMTP_VERIFY_SERVER_CERT, True):
            tls_context.check_hostname = False
            tls_context.verify_mode = ssl.CERT_NONE

        # if it is SSL, (not None or StartTLS) then the function to call is different
        if ssl_config == SSL_CONFIG_SSL:
            func_to_use = getattr(smtplib, "SMTP_SSL")

        # use the port if specified
        if SMTP_JSON_PORT in config:
            ret_val, port_data = self._validate_integer(action_result, config[SMTP_JSON_PORT], SMTP_JSON_PORT, True)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, port_data)

            connection_kwargs = {"context": tls_context} if ssl_config == SSL_CONFIG_SSL else {}
            self._smtp_conn = func_to_use(server, str(port_data), **connection_kwargs)
        else:
            connection_kwargs = {"context": tls_context} if ssl_config == SSL_CONFIG_SSL else {}
            self._smtp_conn = func_to_use(server, **connection_kwargs)

        self._smtp_conn.ehlo()

        # Use the StartTLS command if the config was set to StartTLS
        if ssl_config == SSL_CONFIG_STARTTLS:
            self._smtp_conn.starttls(context=tls_context)

        self._smtp_conn.ehlo()
        # Login
        try:
            self.debug_print("Attempting to login")
            if self._auth_mechanism == SMTP_OAUTH_AUTH_TYPE:
                if config.get(phantom.APP_JSON_USERNAME) is None:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "A username must be specified to run test connectivity using OAuth. Please check your asset configuration.",
                    )
                auth_string = self._generate_oauth_string(config[phantom.APP_JSON_USERNAME], self._access_token)
                # self._smtp_conn.ehlo(config.get("client_id"))
                response_code, response_message = self._smtp_conn.docmd("AUTH", f"XOAUTH2 {auth_string}")
            elif self._auth_mechanism == SMTP_BASIC_AUTH_TYPE:
                self.debug_print("username and password used")
                response_code, response_message = self._smtp_conn.login(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
            elif self._auth_mechanism == SMTP_PASSWORD_LESS_AUTH_TYPE:
                self.debug_print(SMTP_MESSAGE_SKIP_AUTH_NO_USERNAME_PASSWORD)
                response_code, response_message = (None, None)
            else:
                self.debug_print(f"Unsupported auth_mechanism: {self._auth_mechanism}")
                return action_result.set_status(phantom.APP_ERROR, "Login failed due to an unsupported auth mechanism. This shouldn't happen.")

        except Exception as e:
            self.debug_print(f"Exception occurred while attempting to login using OAuth. Details: {e}")
            # If token is expired, use the refresh token to re-new the access token
            error_text = self._get_error_message_from_exception(e)
            if first_try and is_oauth and "Invalid credentials" in error_text:
                self.debug_print("Try to generate token from refresh token")
                ret_val, message = self._interactive_auth_refresh()
                if not ret_val:
                    return action_result.set_status(phantom.APP_ERROR, message)
                return self._connect_to_server(action_result, False)
            raise e

        if response_code is not None:
            self.debug_print(f"Response to login attempt received. Response code: {response_code}")
            # 334 status code for smtp signifies that the requested security mechanism is accepted
            if response_code == 334:
                decoded_bytes = base64.b64decode(response_message)
                decoded_str = decoded_bytes.decode("ascii")
                json_str = json.loads(decoded_str)

                if "gmail" not in config[phantom.APP_JSON_SERVER] and json_str.get("status") == "400":
                    return action_result.set_status(
                        phantom.APP_ERROR, "Could not connect to server, please check your asset configuration and re-run test connectivity"
                    )
                ret_val, message = self._interactive_auth_refresh()
                if not ret_val:
                    return action_result.set_status(phantom.APP_ERROR, message)
                return self._connect_to_server(action_result, False)
            elif response_code == 535:
                ret_val, message = self._interactive_auth_refresh()
                if not ret_val:
                    return action_result.set_status(phantom.APP_ERROR, message)
                return self._connect_to_server(action_result, False)
            elif response_code != 235:
                self.debug_print(f"Error while connecting to SMTP server, Response code: {response_code}, Response: {response_message}")
                return action_result.set_status(
                    phantom.APP_ERROR, f"Logging in error, response_code: {response_code} response: {response_message}"
                )

        self.save_progress(SMTP_SUCC_SMTP_CONNECTIVITY_TO_SERVER)
        return phantom.APP_SUCCESS

    def _attach_bodies(self, outer, body, action_result, message_encoding):
        # first attach the plain if possible
        try:
            soup = BeautifulSoup(body)
            text = soup.get_text()

            # need to decode/encode for utf-8 emails with html
            if message_encoding == "utf-8":
                # text = text.decode('utf-8')
                part_plain = MIMEText(text, "plain", "utf-8")
            else:
                part_plain = MIMEText(text, "plain")

            outer.attach(part_plain)

        except Exception as e:
            self.debug_print(f"Error in converting html body to text {self._get_error_message_from_exception(e)}")

        try:
            # lastly attach html
            if message_encoding == "utf-8":
                part_html = MIMEText(body, "html", "utf-8")
            else:
                part_html = MIMEText(body, "html")

            outer.attach(part_html)
        except Exception as e:
            self.debug_print(f"Error while attaching html body to outer {self._get_error_message_from_exception(e)}")

        return phantom.APP_SUCCESS

    def _set_refused_recipients_error(self, action_result, refused_recipients):
        refused_details = {}
        for recipient, (status_code, response) in refused_recipients.items():
            if isinstance(response, bytes):
                response = response.decode(errors="replace")
            refused_details[recipient] = {"status_code": status_code, "response": str(response)}

        action_result.add_data({"refused_recipients": refused_details})
        action_result.update_summary({"refused_recipients": sorted(refused_details)})
        return action_result.set_status(
            phantom.APP_ERROR,
            f"{SMTP_ERROR_SMTP_SEND_EMAIL}. Server refused the following recipients: {', '.join(sorted(refused_details))}",
        )

    def _add_attachments(self, outer, attachments, action_result, message_encoding):
        if not attachments:
            return phantom.APP_SUCCESS

        for attachment_vault_id in attachments:
            if self.get_container_id() == "0":
                if ".pdf" not in attachment_vault_id:
                    return action_result.set_status(phantom.APP_ERROR, SMTP_ERROR_SMTP_SEND_EMAIL)

                phantom_home_path = self.get_phantom_home()
                report_dir = os.path.join(phantom_home_path, "vault", "reports")

                test_filename = os.path.join(report_dir, attachment_vault_id)
                test_filename = os.path.abspath(test_filename)

                filename = test_filename if os.path.isfile(test_filename) else ""

                is_valid_path = filename.startswith(report_dir)

                if not filename or not is_valid_path:
                    return action_result.set_status(phantom.APP_ERROR, SMTP_ERROR_SMTP_SEND_EMAIL)

                with open(filename, "rb") as fp:
                    msg = MIMEBase("application", "pdf")
                    msg.set_payload(fp.read())

                filename = os.path.basename(filename)
                # handling ugly file names that are of the format "report_type__id-X__ts-<timestamp>.pdf", where 'X' is any number
                if "__" in filename:
                    pieces = filename.split("__")
                    if len(pieces) == 3:
                        filename = f"{pieces[0]}_{pieces[2]}"  # get rid of __id_x__

                # Encode the payload using Base64
                encoders.encode_base64(msg)
            else:
                try:
                    _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=attachment_vault_id)
                    if not vault_meta_info:
                        _, _, vault_meta_info = ph_rules.vault_info(vault_id=attachment_vault_id)
                        if not vault_meta_info:
                            self.invalid_vault_ids.append(attachment_vault_id)
                            continue
                    vault_meta_info = list(vault_meta_info)
                except Exception:
                    self.invalid_vault_ids.append(attachment_vault_id)
                    continue

                # Check if we have any results
                if len(vault_meta_info) == 0:
                    continue

                # pick up the first one, they all point to the same file
                vault_meta_info = vault_meta_info[0]

                attachment_path = vault_meta_info["name"]
                file_path = vault_meta_info["path"]

                # Guess the content type based on the file's extension.  Encoding
                # will be ignored, although we should check for simple things like
                # gzip'd or compressed files.
                filename = os.path.basename(attachment_path)
                ctype, encoding = mimetypes.guess_type(attachment_path)
                if ctype is None or encoding is not None:
                    # No guess could be made, or the file is encoded (compressed), so
                    # use a generic bag-of-bits type.
                    ctype = "application/octet-stream"
                maintype, subtype = ctype.split("/", 1)
                try:
                    if maintype == "text":
                        fp = open(file_path)
                        # Note: we should handle calculating the charset
                        msg = MIMEText(fp.read(), _subtype=subtype)
                        fp.close()
                    elif maintype == "message":
                        with open(file_path, "rb") as fp:
                            base_msg = message_from_bytes(fp.read())
                        msg = MIMEMessage(base_msg, _subtype=subtype)
                    elif maintype == "image":
                        fp = open(file_path, "rb")
                        msg = MIMEImage(fp.read(), _subtype=subtype)
                        fp.close()
                    else:
                        fp = open(file_path, "rb")
                        msg = MIMEBase(maintype, subtype)
                        msg.set_payload(fp.read())
                        fp.close()
                        # Encode the payload using Base64
                        encoders.encode_base64(msg)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))

            # Set the filename parameter
            msg.add_header("Content-Disposition", "attachment", filename=filename)
            outer.attach(msg)

        return phantom.APP_SUCCESS

    def _is_html(self, body):
        # first lower it
        body_lower = body.lower()
        if re.match(r"^<!doctype\s+html.*?>", body_lower) or re.match(r"^<html.*?>", body_lower):
            return True
        return False

    def _clean_from_field(self, value: str) -> str:
        """
        Clean the `from` field values by extracting the display name and email
        from strings containing `<mailto:...>`.

        Problem Reference (PAPP-34182):
        --------------------------------
        Based on internal testing (see attached compatibility matrix):
        - On Python 3.9.21(6.4.1 and above), inputs containing <mailto:...> failed to parse:
                "JohnDoe<mailto:john@example.com>"
                "John Doe<mailto:john@example.com>"
        - On Python 3.9.9 (6.4.0) and below, the same inputs parsed successfully:
                "JohnDoe<mailto:john@example.com>"
                "John Doe<mailto:john@example.com>"
        - Already-cleaned values without <mailto:...> work across all versions:
                "John Doe <john@example.com>"
                "JohnDoe <john@example.com>"
                "John Doe john@example.com"
                "JohnDoe john@example.com"

        Compatibility Fix:
        ------------------
        To ensure consistent behavior for existing customer environments,
        this function adds a backward-compatibility layer. It:
        1. Detects values in the format "<mailto:...>"
        2. Extracts the display name and email
        3. Returns them as "name email"
        4. Falls back safely to returning the original value if unmatched

        Parameters
        ----------
        value : str
            The raw `from` field string.

        Returns
        -------
        str
            Cleaned "name email" string if <mailto:...> is detected,
            otherwise the input value unchanged.
        """

        # Regex to capture "Name<mailto:email>"
        match = re.match(r"^(.*?)<mailto:(.*?)>$", value.strip())
        if match:
            name = match.group(1).strip()
            email = match.group(2).strip()
            return f"{name} {email}"

        # Fallback: return the value unchanged if no <mailto:...> found
        return value

    def _send_email(self, param, action_result):
        # username = self.get_config()[phantom.APP_JSON_USERNAME]
        config = self.get_config()

        # Derive 'from' email address
        sender_address = config.get("sender_address", config.get(phantom.APP_JSON_USERNAME))
        email_from = self._clean_from_field(param.get(SMTP_JSON_FROM, sender_address))

        encoding = config.get(SMTP_ENCODING, False)
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)
        body = param[SMTP_JSON_BODY]

        if not email_from:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email sender")

        if encoding:
            message_encoding = "utf-8"
        else:
            message_encoding = "ascii"

        outer = None
        attachments = None

        if SMTP_JSON_ATTACHMENTS in param:
            attachments = param[SMTP_JSON_ATTACHMENTS]
            attachments = [x.strip() for x in attachments.split(",")]
            attachments = list(filter(None, attachments))

        try:
            if self._is_html(body):
                outer = MIMEMultipart("alternative")
                self._attach_bodies(outer, body, action_result, message_encoding)
            elif attachments:
                # it is not html, but has attachments
                outer = MIMEMultipart()
                msg = MIMEText(param[SMTP_JSON_BODY], "plain", message_encoding)
                outer.attach(msg)
            else:
                outer = MIMEText(param[SMTP_JSON_BODY], "plain", message_encoding)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_UNICODE_ERROR_MESSAGE}. {self._get_error_message_from_exception(e)}")

        if SMTP_JSON_HEADERS in param:
            try:
                headers = json.loads(param[SMTP_JSON_HEADERS])
                if not isinstance(headers, dict):
                    raise Exception
                try:
                    for header, value in headers.iteritems():
                        outer[header] = value
                except Exception:
                    for header, value in headers.items():
                        outer[header] = value
            except Exception:
                # Break and return error if headers is not a correctly formatted dict.
                return action_result.set_status(phantom.APP_ERROR, SMTP_ERROR_PARSE_HEADERS.format(param[SMTP_JSON_HEADERS]))

        to_comma_sep_list = param[SMTP_JSON_TO]
        cc_comma_sep_list = param.get(SMTP_JSON_CC, None)
        bcc_comma_sep_list = param.get(SMTP_JSON_BCC, None)

        if SMTP_JSON_SUBJECT in param:
            outer["Subject"] = param[SMTP_JSON_SUBJECT]
            action_result.update_param({SMTP_JSON_SUBJECT: param[SMTP_JSON_SUBJECT]})

        if "From" in outer and param.get(SMTP_JSON_FROM):
            del outer["From"]
            outer["From"] = self._clean_from_field(param[SMTP_JSON_FROM])
        elif "From" in outer:
            email_from = outer["From"]
        else:
            outer["From"] = email_from
        action_result.update_param({SMTP_JSON_FROM: outer["From"]})

        to_list = [x.strip() for x in to_comma_sep_list.split(",")]
        to_list = list(filter(None, to_list))
        outer["To"] = ", ".join(to_list)

        if cc_comma_sep_list:
            cc_list = [x.strip() for x in cc_comma_sep_list.split(",")]
            cc_list = list(filter(None, cc_list))
            to_list.extend(cc_list)
            outer["CC"] = ",".join(cc_list)

        if bcc_comma_sep_list:
            bcc_list = [x.strip() for x in bcc_comma_sep_list.split(",")]
            bcc_list = list(filter(None, bcc_list))
            to_list.extend(bcc_list)

        self._add_attachments(outer, attachments, action_result, message_encoding)

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            refused_recipients = self._smtp_conn.sendmail(email_from, to_list, outer.as_bytes(policy=SMTP), mail_options=mail_options)
            if refused_recipients:
                return self._set_refused_recipients_error(action_result, refused_recipients)
        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {SMTP_ERROR_SMTPUTF8_CONFIG}")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {self._get_error_message_from_exception(e)}")

        if self.invalid_vault_ids:
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "{}. The following attachments are invalid and were not sent: {}".format(
                    SMTP_SUCC_SMTP_EMAIL_SENT, ", ".join(self.invalid_vault_ids)
                ),
            )

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def _handle_send_email(self, param, action_result=None):
        action_id = self.get_action_identifier()

        if action_result is None:
            action_result = self.add_action_result(ActionResult(dict(param)))

        # Check auth type and connect to the server
        if action_id != self.ACTION_ID_TEST_CONNECTIVITY:
            self.debug_print("Checking auth type and connecting to the server")
            if phantom.is_fail(self._process_auth_type(action_result)):
                return action_result.get_status()

        try:
            status_code = self._send_email(param, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {self._get_error_message_from_exception(e)}")

        return status_code

    def _generate_oauth_string(self, username, access_token):
        """Generates an SMTP OAuth2 authentication string.

        Args:
            username: the username (email address) of the account to authenticate
            access_token: An OAuth2 access token.

        Returns:
            The SASL argument for the OAuth2 mechanism.
        """
        auth_string = f"user={username}\1auth=Bearer {access_token}\1\1"
        auth_string = base64.b64encode(auth_string.encode()).decode()

        return auth_string

    def _connect_to_server_helper(self, action_result):
        """Redirect the flow based on auth type"""
        self.debug_print("Connecting to SMTP server")
        if self._auth_mechanism == SMTP_OAUTH_AUTH_TYPE:
            if self._refresh_token and self._access_token == "":
                self.debug_print("Try to generate token from refresh token")
                ret_val, message = self._interactive_auth_refresh()
                if not ret_val:
                    return action_result.set_status(phantom.APP_ERROR, message)
                status_code = self._connect_to_server(action_result)

            ret_val, message = self._set_interactive_auth(action_result)
            if not ret_val:
                return action_result.set_status(phantom.APP_ERROR, message)

            return phantom.APP_SUCCESS
        else:
            try:
                status_code = self._connect_to_server(action_result)
            except Exception as e:
                return self._parse_connection_error(action_result, e)

            return status_code

    def _test_connectivity(self, param):
        # There could be multiple ways to configure an SMTP server.
        # Even a username and password could be optional.
        # So the best way to test connectivity is to send an email.

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        # Check auth type and connect to the server
        self.debug_print("Checking auth type and connecting to the server")
        if phantom.is_fail(self._process_auth_type(action_result)):
            action_result.append_to_message(SMTP_ERROR_CONNECTIVITY_TEST.format(config.get("auth_type", self._auth_mechanism)))
            return action_result.get_status()

        if self._auth_mechanism == SMTP_PASSWORD_LESS_AUTH_TYPE:
            self.save_progress(SMTP_SUCC_CONNECTIVITY_TEST.format(self._auth_mechanism))  # nosemgrep
            return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_CONNECTIVITY_TEST.format(self._auth_mechanism))

        param = {
            SMTP_JSON_TO: (config.get("sender_address") or config[phantom.APP_JSON_USERNAME]),
            SMTP_JSON_FROM: (config.get("sender_address") or config[phantom.APP_JSON_USERNAME]),
            SMTP_JSON_SUBJECT: "Test SMTP config",
            SMTP_JSON_BODY: "This is a test mail, sent by the SOAR device,\nto test connectivity to the SMTP Asset.",
        }

        self.debug_print(param, param)

        self.save_progress(SMTP_SENDING_TEST_MAIL)
        if phantom.is_fail(self._handle_send_email(param, action_result)):
            self.debug_print("connect failed")
            self.save_progress(f"Error message: {action_result.get_message()}")
            return action_result.set_status(
                phantom.APP_ERROR, SMTP_ERROR_CONNECTIVITY_TEST.format(config.get("auth_type", self._auth_mechanism))
            )

        self.save_progress(SMTP_DONE)

        self.debug_print("connect passed")
        self.save_progress(SMTP_SUCC_CONNECTIVITY_TEST.format(self._auth_mechanism))  # nosemgrep
        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_CONNECTIVITY_TEST.format(self._auth_mechanism))

    def html_to_text(self, html):
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator=" ")
        return text

    def _handle_send_htmlemail(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))

        # Check auth type and connect to the server
        self.debug_print("Checking auth type and connecting to the server")
        if phantom.is_fail(self._process_auth_type(action_result)):
            return action_result.get_status()

        config = self.get_config()

        # Derive 'from' email address
        sender_address = config.get("sender_address", config.get(phantom.APP_JSON_USERNAME))
        email_from = self._clean_from_field(param.get(SMTP_JSON_FROM, sender_address))

        email_to = param["to"]
        email_cc = param.get("cc")
        email_bcc = param.get("bcc")
        # Filter method returns a Filter object on Python v3 and a List on Python v2
        # So, to maintain the uniformity the Filter object has been explicitly type casted to List
        email_to = [x.strip() for x in email_to.split(",")]
        email_to = list(filter(None, email_to))

        if email_cc:
            email_cc = [x.strip() for x in email_cc.split(",")]
            email_cc = list(filter(None, email_cc))

        if email_bcc:
            email_bcc = [x.strip() for x in email_bcc.split(",")]
            email_bcc = list(filter(None, email_bcc))

        email_subject = param.get("subject")
        email_headers = param.get("headers")
        email_html = param["html_body"]
        email_text = param.get("text_body")
        attachment_json = param.get("attachment_json")
        should_sanitize = param.get("should_sanitize_template", True)

        if should_sanitize:
            try:
                email_html = tidy_document(
                    email_html,
                    options={
                        OptionId.word2000: True,
                        OptionId.drop_prop_attrs: True,
                        OptionId.html_out: True,
                        OptionId.mark: False,
                        OptionId.drop_empty_paras: False,
                        OptionId.drop_empty_elems: False,
                    },
                    encoding="unicode",
                    body_only=True,
                    quiet=True,
                )
                email_html = bleach.clean(
                    text=email_html,
                    tags=self.SAFE_HTML_TAGS,
                    attributes=BLEACH_SAFE_HTML_ATTRIBUTES,
                    css_sanitizer=CSSSanitizer(allowed_css_properties=all_styles),
                    protocols=list(bleach.ALLOWED_PROTOCOLS) + SMTP_BLEACH_ALLOWED_PROTOCOLS,
                    strip=True,
                )
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Error: failed to sanitize HTML body")

        encoding = config.get(SMTP_ENCODING, False)
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)

        if encoding:
            message_encoding = "utf-8"
        else:
            message_encoding = "ascii"

        # Validation for the 'from' email address
        if not email_from:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email sender")

        if not len(email_to):
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email recipients")

        if email_headers:
            try:
                email_headers = json.loads(email_headers)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Error: custom email headers field is not valid json")

            if not isinstance(email_headers, dict):
                return action_result.set_status(phantom.APP_ERROR, "Error: custom email headers field is not a dictionary")

        else:
            email_headers = {}

        if attachment_json:
            try:
                attachment_json = json.loads(attachment_json)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Error: attachment json field is not valid json")

            if not isinstance(attachment_json, list):
                return action_result.set_status(phantom.APP_ERROR, "Error: attachment json field is not a list")

            has_dictionary = False
            for x in attachment_json:
                if isinstance(x, dict) and x.get("vault_id"):
                    has_dictionary = True
                    break

            if not has_dictionary:
                return action_result.set_status(
                    phantom.APP_ERROR, 'Error: attachment json field does not contain any dictionaries with the "vault_id" key'
                )

            for attachment in attachment_json:
                for key, value in list(attachment.items()):
                    attachment.pop(key)
                    attachment[key] = value

        else:
            attachment_json = []

        for i in range(1, 6):
            attachment_json += [{"vault_id": param.get(f"attachment{i}"), "content_id": param.get(f"content_id{i}")}]

        attachment_json = list(filter(lambda x: isinstance(x, dict) and x.get("vault_id"), attachment_json))

        root = MIMEMultipart("related")

        root["to"] = ",".join(email_to)

        if email_cc:
            root["cc"] = ", ".join(email_cc)
            email_to.extend(email_cc)

        if email_bcc:
            email_to.extend(email_bcc)

        if email_subject:
            root["subject"] = email_subject

        for k, v in list(email_headers.items()):
            root[k] = v

        if not email_text:
            email_text = self.html_to_text(email_html)

        if "From" in root and param.get(SMTP_JSON_FROM):
            del root["From"]
            root["From"] = self._clean_from_field(param[SMTP_JSON_FROM])
        elif "From" in root:
            email_from = root["From"]
        else:
            root["From"] = email_from

        msg = MIMEMultipart("alternative")

        try:
            if message_encoding == "utf-8":
                msg.attach(MIMEText(email_text, "plain", "utf-8"))
                msg.attach(MIMEText(email_html, "html", "utf-8"))
            else:
                msg.attach(MIMEText(email_text, "plain", "ascii"))
                msg.attach(MIMEText(email_html, "html", "ascii"))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_UNICODE_ERROR_MESSAGE}. {self._get_error_message_from_exception(e)}")
        root.attach(msg)

        for x in attachment_json:
            vault_id = x["vault_id"]
            content_id = x.get("content_id")
            try:
                _, _, data = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
                if not data:
                    _, _, data = ph_rules.vault_info(vault_id=vault_id)
                data = list(data)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, f"Error: failed to find vault ID: {vault_id}")

            if data and len(data) > 0 and isinstance(data[0], dict) and data[0].get("path"):
                path = data[0].get("path")

                attachment_path = data[0].get("name")
                filename = os.path.basename(attachment_path)
                ctype, encoding = mimetypes.guess_type(attachment_path)
                if ctype is None:
                    ctype = "application/octet-stream"
                maintype, subtype = ctype.split("/", 1)

                try:
                    if maintype == "text":
                        with open(path) as fp:
                            attachment = MIMEText(fp.read(), _subtype=subtype)

                    elif maintype == "message":
                        with open(path, "rb") as fp:
                            base_msg = message_from_bytes(fp.read())
                            attachment = MIMEMessage(base_msg, _subtype=subtype)

                    elif maintype == "image":
                        # Python 2to3 change
                        with open(path, "rb") as fp:
                            attachment = MIMEImage(fp.read(), _subtype=subtype)

                    else:
                        with open(path, "rb") as rfp:
                            attachment = MIMEBase(maintype, subtype)
                            attachment.set_payload(rfp.read())
                            encoders.encode_base64(attachment)

                except Exception:
                    return action_result.set_status(phantom.APP_ERROR, f"Error: failed to read the file for the vault ID: {vault_id}")

                if content_id:
                    attachment.add_header("Content-ID", "<{}>".format(content_id.strip().lstrip("<").rstrip(">").strip()))
                else:
                    attachment.add_header("Content-Disposition", "attachment", filename=filename)
                root.attach(attachment)

            else:
                return action_result.set_status(phantom.APP_ERROR, f"Error: failed to find vault id: {vault_id}")

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            refused_recipients = self._smtp_conn.sendmail(email_from, email_to, root.as_bytes(policy=SMTP), mail_options=mail_options)
            if refused_recipients:
                return self._set_refused_recipients_error(action_result, refused_recipients)

        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {SMTP_ERROR_SMTPUTF8_CONFIG}")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {self._get_error_message_from_exception(e)}")

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def _handle_send_rawemail(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))

        # Check auth type and connect to the server
        self.debug_print("Checking auth type and connecting to the server")
        if phantom.is_fail(self._process_auth_type(action_result)):
            return action_result.get_status()

        config = self.get_config()
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)
        raw_email = param["raw_email"]
        raw_email = raw_email.replace("\\n", "\n")
        msg = message_from_string(raw_email)
        email_from = msg.get("from", "")
        email_to_str = msg.get("to", "")
        # email_to = ",".join(filter(lambda x: x, [ msg['to'], msg['cc'], msg['bcc'] ]))
        # email_to = [y for x in email_to.split(',') for y in x.split() if y]
        # Filter method returns a Filter object on Python v3 and a List on Python v2
        # So, to maintain the uniformity the Filter object has been explicitly type casted to List

        if not len(email_from):
            return action_result.set_status(phantom.APP_ERROR, SMTP_ERROR_TO_FROM_UNAVAILABLE.format("sender (from)"))

        # In case the user provides 'CC' or 'BCC' but does not provide 'To'
        if not len(email_to_str):
            return action_result.set_status(phantom.APP_ERROR, SMTP_ERROR_TO_FROM_UNAVAILABLE.format("recipient (to)"))

        email_to = [x.strip() for x in msg["to"].split(",")]
        if msg["cc"]:
            email_to.extend([x.strip() for x in msg["cc"].split(",")])
        if msg["bcc"]:
            email_to.extend([x.strip() for x in msg["bcc"].split(",")])
            # Remove BCC field from the headers as we do not want to display it in the email's headers
            for header in msg._headers:
                if header[0].lower() == "bcc":
                    msg._headers.remove(header)

        email_to = list(filter(None, email_to))

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            self.debug_print("Making SMTP call")
            refused_recipients = self._smtp_conn.sendmail(email_from, email_to, msg.as_bytes(policy=SMTP), mail_options=mail_options)
            if refused_recipients:
                return self._set_refused_recipients_error(action_result, refused_recipients)

        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {SMTP_ERROR_SMTPUTF8_CONFIG}")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{SMTP_ERROR_SMTP_SEND_EMAIL}. {self._get_error_message_from_exception(e)}")

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()
        ret_val = phantom.APP_ERROR

        if action == self.ACTION_ID_SEND_EMAIL:
            ret_val = self._handle_send_email(param)
        elif action == self.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == self.ACTION_ID_SEND_RAW_EMAIL:
            ret_val = self._handle_send_rawemail(param)
        elif action == self.ACTION_ID_SEND_HTML_EMAIL:
            ret_val = self._handle_send_htmlemail(param)

        return ret_val


if __name__ == "__main__":
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SmtpConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SmtpConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
