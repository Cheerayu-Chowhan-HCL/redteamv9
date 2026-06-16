"""
ResponseSanitiser — strips HTML/JS from HTTP responses before returning to agent.
Defends against prompt injection via malicious web page content.
"""
import re
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_EVENT_RE = re.compile(r"\s+on\w+\s*=\s*['\"][^'\"]*['\"]", re.IGNORECASE)
_IFRAME_RE = re.compile(r"<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL)
_BASE64_RE = re.compile(r"(?:data:[^;]+;base64,)[A-Za-z0-9+/=]+", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_MULTI_SPACE = re.compile(r"\s{3,}")


def response_sanitiser(raw_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw HTTP response dict into a safe summary for the agent.
    Strips scripts, inline handlers, base64 blobs, iframe src values.
    Returns: status_code, headers, plain_text_summary, form_fields, links.
    """
    body = raw_response.get("body", "") or ""
    status_code = raw_response.get("status_code", 0)
    headers = raw_response.get("headers", {})
    url = raw_response.get("url", "")

    # Strip dangerous content
    clean = _SCRIPT_RE.sub("", body)
    clean = _EVENT_RE.sub("", clean)
    clean = _IFRAME_RE.sub("", clean)
    clean = _BASE64_RE.sub("[BASE64 REMOVED]", clean)

    # Extract forms
    form_fields = _extract_forms(body)
    links = _extract_links(body)

    # Strip remaining HTML tags for plain text
    plain = _TAG_RE.sub(" ", clean)
    plain = _MULTI_SPACE.sub(" ", plain).strip()

    # Truncate to safe size
    if len(plain) > 2000:
        plain = plain[:2000] + "... [TRUNCATED]"

    # Filter headers — keep structural ones only
    safe_headers = {k: v for k, v in headers.items()
                    if k.lower() in (
                        "content-type", "server", "x-powered-by", "location",
                        "set-cookie", "www-authenticate", "content-length",
                        "x-frame-options", "content-security-policy",
                        "strict-transport-security", "x-content-type-options"
                    )}

    return {
        "status_code": status_code,
        "url": url,
        "headers": safe_headers,
        "plain_text_summary": plain,
        "form_fields": form_fields,
        "links": links[:50],  # cap at 50 links
        "content_length": len(body),
    }


def _extract_forms(html: str) -> list:
    forms = []
    form_re = re.compile(r"<form([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    input_re = re.compile(r"<input([^>]*)>", re.IGNORECASE)
    select_re = re.compile(r"<select([^>]*)>", re.IGNORECASE)
    textarea_re = re.compile(r"<textarea([^>]*)>", re.IGNORECASE)
    attr_re = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')

    for fm in form_re.finditer(html):
        attrs = dict(attr_re.findall(fm.group(1)))
        fields = []
        for inp in input_re.finditer(fm.group(2)):
            ia = dict(attr_re.findall(inp.group(1)))
            name = ia.get("name", "")
            itype = ia.get("type", "text")
            if name:
                fields.append({"name": name, "type": itype})
        for sel in select_re.finditer(fm.group(2)):
            sa = dict(attr_re.findall(sel.group(1)))
            if sa.get("name"):
                fields.append({"name": sa["name"], "type": "select"})
        for ta in textarea_re.finditer(fm.group(2)):
            ta_a = dict(attr_re.findall(ta.group(1)))
            if ta_a.get("name"):
                fields.append({"name": ta_a["name"], "type": "textarea"})
        forms.append({
            "action": attrs.get("action", ""),
            "method": attrs.get("method", "GET").upper(),
            "fields": fields,
        })
    return forms


def _extract_links(html: str) -> list:
    href_re = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    return [m.group(1) for m in href_re.finditer(html)]
