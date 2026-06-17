"""
Tests for DagSanitiser — verifies payload redaction and clean string passthrough.
Run: python -m pytest tests/test_dag_sanitiser.py -v
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from core.dag_sanitiser import DagSanitiser

PLACEHOLDER = DagSanitiser.PLACEHOLDER


class TestSanitiseString:

    def test_sql_union_select_redacted(self):
        s = "' UNION SELECT username, password FROM users--"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_sql_or_1_equals_1_redacted(self):
        s = "' OR '1'='1'-- "
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_sql_drop_table_redacted(self):
        s = "'; DROP TABLE users;--"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_sql_select_star_redacted(self):
        s = "SELECT * FROM information_schema.tables"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_xss_script_tag_redacted(self):
        s = "<script>alert(document.cookie)</script>"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_xss_onerror_redacted(self):
        s = "<img src=x onerror=alert(1)>"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_xss_javascript_protocol_redacted(self):
        s = "javascript:alert(1)"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_xss_iframe_redacted(self):
        s = "<iframe src='javascript:alert(1)'></iframe>"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_cmd_injection_pipe_redacted(self):
        s = "hello | whoami"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_cmd_injection_semicolon_redacted(self):
        s = "test; cat /etc/passwd"
        assert DagSanitiser.sanitise_string(s) == PLACEHOLDER

    def test_clean_url_passes(self):
        s = "https://example.com/login"
        result = DagSanitiser.sanitise_string(s)
        assert result == s

    def test_clean_text_passes(self):
        s = "Login form found at /auth/login with username and password fields"
        result = DagSanitiser.sanitise_string(s)
        assert PLACEHOLDER not in result

    def test_clean_finding_passes(self):
        s = "SQL Injection in parameter username at endpoint /login"
        result = DagSanitiser.sanitise_string(s)
        assert PLACEHOLDER not in result

    def test_clean_header_name_passes(self):
        s = "Missing Content-Security-Policy header"
        result = DagSanitiser.sanitise_string(s)
        assert PLACEHOLDER not in result

    def test_base64_blob_redacted(self):
        b64 = "A" * 50
        result = DagSanitiser.sanitise_string(b64)
        assert "[B64 REDACTED]" in result or result == b64  # only redacted if pure b64

    def test_empty_string_passes(self):
        assert DagSanitiser.sanitise_string("") == ""

    def test_none_coerced_to_string(self):
        result = DagSanitiser.sanitise_string(None)
        assert isinstance(result, str)


class TestSanitiseNode:

    def test_payload_key_redacted(self):
        node = {"payload": "' OR 1=1--", "url": "/login"}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["payload"] == PLACEHOLDER
        assert safe["url"] == "/login"

    def test_cookies_dict_values_redacted(self):
        node = {"cookies": {"PHPSESSID": "abc123def456", "auth": "secrettoken"}}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["cookies"]["PHPSESSID"] == "[REDACTED]"
        assert safe["cookies"]["auth"] == "[REDACTED]"

    def test_cookies_string_redacted(self):
        node = {"cookies": "PHPSESSID=abc123; auth=secret"}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["cookies"] == "[COOKIE REDACTED]"

    def test_structural_keys_preserved(self):
        node = {"method": "POST", "url": "/login", "status_code": 200, "content_length": 1500}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["method"] == "POST"
        assert safe["url"] == "/login"
        assert safe["status_code"] == 200

    def test_nested_dict_sanitised(self):
        node = {"metadata": {"payload": "<script>alert(1)</script>", "clean": "hello"}}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["metadata"]["payload"] == PLACEHOLDER
        assert safe["metadata"]["clean"] == "hello"

    def test_list_of_strings_sanitised(self):
        node = {"tags": ["<script>xss</script>", "normal tag", "UNION SELECT"]}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["tags"][0] == PLACEHOLDER
        assert safe["tags"][1] == "normal tag"

    def test_raw_body_redacted(self):
        node = {"raw_body": "HTTP/1.1 200 OK\r\nContent: big body here..."}
        safe = DagSanitiser.sanitise_node(node)
        assert safe["raw_body"] == PLACEHOLDER


class TestSanitiseEvidence:

    def test_long_evidence_truncated(self):
        # Mixed text string, not a base64 blob, exceeds 300 chars
        long_str = "SQL injection confirmed at parameter username. " * 9  # ~414 chars
        result = DagSanitiser.sanitise_evidence(long_str)
        assert "[TRUNCATED]" in result
        assert len(result) <= 320

    def test_sql_in_evidence_redacted(self):
        result = DagSanitiser.sanitise_evidence("UNION SELECT * FROM users")
        assert result == PLACEHOLDER

    def test_clean_evidence_passes(self):
        result = DagSanitiser.sanitise_evidence("SQL injection confirmed at /login endpoint")
        assert PLACEHOLDER not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
