# File: test_smtp_messages.py
#
# Copyright (c) 2026 Splunk Inc.
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

"""Run with the SOAR Python environment: python -m unittest discover -s tests."""

import json
import smtplib
import socketserver
import tempfile
import threading
import unittest
from email import message_from_bytes
from pathlib import Path
from unittest.mock import Mock, patch

import phantom.app as phantom
from phantom.action_result import ActionResult

import smtp_connector


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 localhost test SMTP\r\n")
        while line := self.rfile.readline():
            command = line.split(None, 1)[0].upper()
            if command in (b"EHLO", b"HELO"):
                self.wfile.write(b"250-localhost\r\n250-8BITMIME\r\n")
                if self.server.utf8:
                    self.wfile.write(b"250-SMTPUTF8\r\n")
                self.wfile.write(b"250 HELP\r\n")
            elif command == b"MAIL":
                self.server.mail_commands.append(line)
                self.wfile.write(b"250 OK\r\n")
            elif command == b"RCPT":
                code = b"550 refused" if b"refused@" in line else b"250 OK"
                self.wfile.write(code + b"\r\n")
            elif command == b"DATA":
                self.wfile.write(b"354 send message\r\n")
                lines = []
                while (part := self.rfile.readline()) not in (b".\r\n", b""):
                    lines.append(part[1:] if part.startswith(b"..") else part)
                self.server.messages.append(b"".join(lines))
                self.wfile.write(b"250 accepted\r\n")
            elif command == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n")


class SMTPMessagesTest(unittest.TestCase):
    def setUp(self):
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTPHandler)
        self.server.daemon_threads = True
        self.server.utf8 = False
        self.server.messages = []
        self.server.mail_commands = []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.attachment = Path(self.temp.name) / "forwarded.eml"
        self.attachment.write_bytes(
            b"From: original@example.com\r\nTo: recipient@example.com\r\n"
            b"Subject: forwarded message\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n\r\ncaf\xc3\xa9 \xe2\x98\x83\r\n"
        )
        vault = patch.object(
            smtp_connector.ph_rules,
            "vault_info",
            return_value=(True, "", [{"name": self.attachment.name, "path": str(self.attachment)}]),
        )
        vault.start()
        self.addCleanup(vault.stop)

    def send(self, action, utf8=False, recipients="recipient@example.com"):
        self.server.utf8 = utf8
        connector = smtp_connector.SmtpConnector()
        connector.get_config = Mock(return_value={"sender_address": "sender@example.com", "allow_smtputf8": utf8})
        connector.get_container_id = Mock(return_value=1)
        connector._process_auth_type = Mock(return_value=phantom.APP_SUCCESS)
        connector._smtp_conn = smtplib.SMTP(*self.server.server_address, timeout=5)
        self.addCleanup(connector._smtp_conn.close)
        if action == "email":
            result = ActionResult({})
            status = connector._send_email({"to": recipients, "body": "message body", "attachments": "vault-id"}, result)
        elif action == "html":
            status = connector._handle_send_htmlemail(
                {
                    "to": recipients,
                    "html_body": "<html><body>message body</body></html>",
                    "text_body": "message body",
                    "attachment_json": json.dumps([{"vault_id": "vault-id"}]),
                    "should_sanitize_template": False,
                }
            )
            result = connector.get_action_results()[-1]
        else:
            status = connector._handle_send_rawemail(
                {"raw_email": f"From: sender@example.com\nTo: {recipients}\nSubject: raw\n\nline one\n.line two\n"}
            )
            result = connector.get_action_results()[-1]
        return status, result

    def assert_wire_message(self):
        wire = self.server.messages[-1]
        self.assertNotIn(b"\n", wire.replace(b"\r\n", b""))
        return message_from_bytes(wire)

    def test_unicode_message_attachment_without_smtputf8(self):
        for action in ("email", "html"):
            with self.subTest(action=action):
                status, result = self.send(action)
                self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
                message = self.assert_wire_message()
                inner = next(part for part in message.walk() if part.get_content_type() == "message/rfc822").get_payload(0)
                self.assertEqual(inner.get_payload(decode=True), "café ☃\r\n".encode())
                self.assertNotIn(b"SMTPUTF8", self.server.mail_commands[-1])

    def test_non_utf8_message_attachment(self):
        self.attachment.write_bytes(
            self.attachment.read_bytes().replace(b"charset=utf-8", b"charset=iso-8859-1").replace("café ☃".encode(), b"caf\xe9")
        )
        for action in ("email", "html"):
            with self.subTest(action=action):
                status, result = self.send(action)
                self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
                message = self.assert_wire_message()
                inner = next(part for part in message.walk() if part.get_content_type() == "message/rfc822").get_payload(0)
                self.assertEqual(inner.get_payload(decode=True), b"caf\xe9\r\n")

    def test_unicode_envelope_requires_smtputf8(self):
        for utf8 in (False, True):
            for action in ("email", "html", "raw"):
                with self.subTest(action=action, utf8=utf8):
                    status, result = self.send(action, utf8=utf8, recipients="récipient@example.com")
                    self.assertEqual(status, phantom.APP_SUCCESS if utf8 else phantom.APP_ERROR, result.get_message())

    def test_all_actions_use_crlf(self):
        for action in ("email", "html", "raw"):
            with self.subTest(action=action):
                status, result = self.send(action)
                self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
                self.assert_wire_message()
        self.assertIn(b"\r\n.line two\r\n", self.server.messages[-1])

    def test_smtputf8_option_is_preserved(self):
        for action in ("email", "html", "raw"):
            with self.subTest(action=action):
                status, result = self.send(action, utf8=True)
                self.assertEqual(status, phantom.APP_SUCCESS, result.get_message())
                self.assertIn(b"SMTPUTF8", self.server.mail_commands[-1])

    def test_partial_recipient_refusal_remains_an_error(self):
        for action in ("email", "html", "raw"):
            with self.subTest(action=action):
                status, result = self.send(action, recipients="recipient@example.com,refused@example.com")
                self.assertEqual(status, phantom.APP_ERROR)
                self.assertIn("refused@example.com", result.get_message())


if __name__ == "__main__":
    unittest.main()
