from __future__ import annotations

import json
import unittest

from scheduler.evidence import redact_text


class EvidenceRedactionTests(unittest.TestCase):
    def test_redacts_common_json_secret_fields_without_breaking_json(self) -> None:
        source = json.dumps(
            {
                "password": "password-value",
                "api_key": "api-key-value",
                "accessToken": "access-token-value",
                "client-secret": "client-secret-value",
                "nested": {
                    "privateKey": "private-key-value",
                    "token": 123456,
                },
                "safe": "visible-value",
            }
        )

        redacted_text = redact_text(source)
        redacted = json.loads(redacted_text)

        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["accessToken"], "[REDACTED]")
        self.assertEqual(redacted["client-secret"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["privateKey"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["token"], "[REDACTED]")
        self.assertEqual(redacted["safe"], "visible-value")
        for secret in (
            "password-value",
            "api-key-value",
            "access-token-value",
            "client-secret-value",
            "private-key-value",
            "123456",
        ):
            self.assertNotIn(secret, redacted_text)

    def test_handles_escaped_json_values_and_does_not_match_similar_keys(self) -> None:
        source = r'{"password":"quoted\"secret","token_count":7,"secretary":"visible"}'

        redacted = json.loads(redact_text(source))

        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["token_count"], 7)
        self.assertEqual(redacted["secretary"], "visible")

    def test_retains_header_assignment_and_known_secret_redaction(self) -> None:
        source = (
            "Authorization: Bearer header-value\n"
            "api_key=assignment-value\n"
            "unstructured known-secret-value"
        )

        redacted = redact_text(source, ("known-secret-value",))

        self.assertNotIn("header-value", redacted)
        self.assertNotIn("assignment-value", redacted)
        self.assertNotIn("known-secret-value", redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 3)


if __name__ == "__main__":
    unittest.main()
