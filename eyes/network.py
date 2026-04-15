"""
Network interception module for capturing API traffic.
Listens to all requests/responses made by the browser during agent operation.
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from playwright.sync_api import Page, Request, Response


# Patterns to identify resource IDs in URLs like /api/Products/5 or /api/Users/3
RESOURCE_ID_PATTERN = re.compile(r'/(\d+)(?:/|$|\?)')

# Patterns to identify resource IDs in JSON response bodies
BODY_ID_PATTERN = re.compile(r'"(?:id|userId|productId|basketId|addressId|cardId)"\s*:\s*(\d+)', re.IGNORECASE)

# Common auth token header names
AUTH_HEADERS = {"authorization", "x-auth-token", "x-access-token", "cookie"}

logger = logging.getLogger(__name__)

# Counter for generating unique request keys (fixes duplicate URL collision)
_request_counter = 0


class NetworkInterceptor:
    """
    Attaches to a Playwright page and records all HTTP traffic.
    Call start_capture() before navigating, get_captured_traffic() after.
    """

    def __init__(self, page: Page):
        self.page = page
        self._requests: Dict[str, Dict] = {}  # keyed by request URL+method+counter
        self._captured: List[Dict[str, Any]] = []  # final merged records
        self._is_capturing = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_capture(self):
        """Begin listening for requests and responses."""
        if self._is_capturing:
            return
        self._captured = []
        self._requests = {}
        self.page.on("request", self._on_request)
        self.page.on("response", self._on_response)
        self._is_capturing = True

    def stop_capture(self):
        """Stop listening. Safe to call multiple times."""
        if not self._is_capturing:
            return
        self.page.remove_listener("request", self._on_request)
        self.page.remove_listener("response", self._on_response)
        self._is_capturing = False

    def get_captured_traffic(self) -> List[Dict[str, Any]]:
        """Return a copy of all captured request/response pairs."""
        return list(self._captured)

    def extract_resource_ids(self) -> List[Dict[str, Any]]:
        """
        Scan captured URLs AND response bodies for numeric resource IDs.
        e.g. /api/Products/5  →  { "url": "...", "endpoint": "Products", "id": "5", "source": "url" }
        e.g. {"id": 5}        →  { "url": "...", "endpoint": "...", "id": "5", "source": "body" }
        """
        found = []

        for record in self._captured:
            url = record.get("url", "")

            # 1. Extract IDs from URL path
            for match in RESOURCE_ID_PATTERN.finditer(url):
                resource_id = match.group(1)
                endpoint = _segment_before_id(url, resource_id)
                found.append({
                    "url": url,
                    "method": record.get("method"),
                    "endpoint": endpoint,
                    "id": resource_id,
                    "source": "url",
                    "timestamp": record.get("timestamp"),
                })

            # 2. Extract IDs from JSON response body
            body = record.get("response_body")
            if body:
                # Serialise to string so we can regex over it regardless of nesting
                try:
                    body_str = json.dumps(body) if not isinstance(body, str) else body
                    for match in BODY_ID_PATTERN.finditer(body_str):
                        resource_id = match.group(1)
                        # Use the URL path to infer endpoint
                        endpoint = _endpoint_from_url(url)
                        found.append({
                            "url": url,
                            "method": record.get("method"),
                            "endpoint": endpoint,
                            "id": resource_id,
                            "source": "body",
                            "timestamp": record.get("timestamp"),
                        })
                except Exception as e:
                    logger.debug("Could not parse response body for IDs from %s: %s", url, e)

        return found

    def extract_auth_tokens(self) -> List[Dict[str, Any]]:
        """
        Scan captured request headers for authentication tokens.
        Returns list of dicts with both a value_preview (for logging)
        and the full value (for programmatic use by Hands/Brain components).
        """
        tokens = []
        for record in self._captured:
            headers = record.get("request_headers", {})
            for header_name, header_value in headers.items():
                if header_name.lower() in AUTH_HEADERS:
                    tokens.append({
                        "url": record.get("url"),
                        "header": header_name,
                        "value": header_value,  # full value for replay use
                        "value_preview": header_value[:40] + "..." if len(header_value) > 40 else header_value,
                        "timestamp": record.get("timestamp"),
                    })
        return tokens

    def summarize_for_llm(self) -> str:
        """Format captured traffic as a concise text block for LLM consumption."""
        if not self._captured:
            return "=== NETWORK TRAFFIC ===\nNo API calls captured.\n"

        lines = [f"=== NETWORK TRAFFIC ({len(self._captured)} requests) ==="]

        # Only show API calls (filter out static assets)
        api_calls = [r for r in self._captured if _is_api_call(r["url"])]
        lines.append(f"API calls: {len(api_calls)}")
        lines.append("")

        for record in api_calls[:20]:  # Cap at 20 to keep LLM prompt small
            status = record.get("status", "?")
            method = record.get("method", "?")
            url    = record.get("url", "?")
            lines.append(f"  {method} {url}  →  {status}")

        if len(api_calls) > 20:
            lines.append(f"  ... and {len(api_calls) - 20} more")

        # Resource IDs found
        ids = self.extract_resource_ids()
        if ids:
            lines.append("")
            lines.append(f"Resource IDs observed: {[i['id'] for i in ids]}")

        # Auth tokens present?
        tokens = self.extract_auth_tokens()
        if tokens:
            lines.append("")
            lines.append(f"Auth headers detected in {len(tokens)} request(s): "
                         f"{list({t['header'] for t in tokens})}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private event handlers
    # ------------------------------------------------------------------

    def _on_request(self, request: Request):
        """Called by Playwright for every outgoing request."""
        key = _request_key(request)
        try:
            body = request.post_data  # None for GET requests
        except Exception:
            body = None

        self._requests[key] = {
            "timestamp": datetime.now().isoformat(),
            "method": request.method,
            "url": request.url,
            "request_headers": dict(request.headers),
            "request_body": body,
            "_key": key,  # store key on record so response handler can find it
            "status": None,
            "response_headers": {},
            "response_body": None,
        }

    def _on_response(self, response: Response):
        """Called by Playwright for every incoming response."""
        key = _request_key(response.request)
        record = self._requests.get(key)

        if record is None:
            # Response arrived before we saw the request — create a minimal record
            record = {
                "timestamp": datetime.now().isoformat(),
                "method": response.request.method,
                "url": response.url,
                "request_headers": {},
                "request_body": None,
            }

        record["status"] = response.status
        record["response_headers"] = dict(response.headers)

        # Try to capture JSON response bodies (skip binary/large responses)
        try:
            content_type = response.headers.get("content-type", "")
            if "json" in content_type:
                record["response_body"] = response.json()
        except Exception:
            record["response_body"] = None

        self._captured.append(record)
        # Remove from pending dict to free memory
        self._requests.pop(key, None)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _request_key(request: Request) -> str:
    """
    Unique key for matching requests to responses.
    Appends a global counter to avoid collisions when the same URL
    is requested multiple times (e.g. Juice Shop polling /api/Products).
    """
    global _request_counter
    _request_counter += 1
    return f"{request.method}:{request.url}:{_request_counter}"


def _segment_before_id(url: str, resource_id: str) -> Optional[str]:
    """
    Given  /api/Products/5  and id '5',  returns 'Products'.
    Returns None if the path structure doesn't match.
    """
    parts = url.split("/")
    try:
        idx = parts.index(resource_id)
        return parts[idx - 1] if idx > 0 else None
    except ValueError:
        return None


def _endpoint_from_url(url: str) -> Optional[str]:
    """
    Extract the last meaningful path segment from a URL as the endpoint label.
    e.g. /api/Products  →  'Products'
         /rest/user/whoami  →  'whoami'
    """
    parts = [p for p in url.split("/") if p and "?" not in p]
    return parts[-1] if parts else None


def _is_api_call(url: str) -> bool:
    """Heuristic: treat URLs containing /api/ or /rest/ as API calls."""
    return "/api/" in url or "/rest/" in url
