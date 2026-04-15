"""
Access Map — the core data structure that enables cross-role comparison.

Stores observed permissions as:
    role -> endpoint -> method -> {status, response_type, has_data, iteration, timestamp}

This allows the Strategy Agent to reason:
    "admin got 200 on GET /api/Users, but we haven't tried this as jim yet"

And allows the Analyzer to reason:
    "jim got 200 on GET /api/Users — admin also got 200 — is this expected?"

Design principles:
    - Target-agnostic: no hardcoded endpoints or application knowledge
    - Built purely from observation: network traffic captured by Eyes
    - Append-only during a run: never deletes observations
    - Serializable: can be exported as JSON for reports and the permission matrix deliverable
"""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Filter out static assets and non-API traffic
_API_PATTERN = re.compile(r'/(api|rest)/', re.IGNORECASE)

# Filter out noisy polling/asset endpoints that aren't interesting for access control
_IGNORE_PATTERNS = [
    re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map)(\?|$)', re.IGNORECASE),
    re.compile(r'/socket\.io/', re.IGNORECASE),
    re.compile(r'/assets/', re.IGNORECASE),
]


def _normalize_endpoint(url: str) -> str:
    """
    Normalize a URL to a comparable endpoint pattern.

    Replaces numeric IDs with {id} so that /api/Users/5 and /api/Users/3
    map to the same endpoint pattern: /api/Users/{id}

    Strips query strings and fragments.

    Examples:
        http://localhost:3000/api/Users/5        -> /api/Users/{id}
        http://localhost:3000/api/Products        -> /api/Products
        http://localhost:3000/rest/user/whoami     -> /rest/user/whoami
        http://localhost:3000/#/administration     -> /#/administration
    """
    # Strip protocol and host
    path = url
    if '://' in url:
        path = '/' + url.split('://', 1)[1].split('/', 1)[-1]

    # Strip query string and fragment for API paths, but keep # for SPA routes
    if '#' in path:
        # SPA route — keep the hash path, strip query
        base, fragment = path.split('#', 1)
        fragment = fragment.split('?')[0]
        path = '/#/' + fragment.lstrip('/')
    else:
        path = path.split('?')[0]

    # Replace numeric IDs with {id}
    path = re.sub(r'/(\d+)(?=/|$)', '/{id}', path)

    return path


def _is_api_call(url: str) -> bool:
    """Check if a URL is an API/REST call worth tracking."""
    # Include both /api/ and /rest/ endpoints
    if _API_PATTERN.search(url):
        return True
    # Also track SPA routes (hash-based navigation)
    if '/#/' in url:
        return True
    return False


def _should_ignore(url: str) -> bool:
    """Check if a URL should be filtered out (static assets, polling, etc.)."""
    for pattern in _IGNORE_PATTERNS:
        if pattern.search(url):
            return True
    return False


def _classify_response(status: int, body: Any) -> Dict[str, Any]:
    """
    Classify a response for access control analysis.

    Returns metadata about what the response reveals:
        - has_data: whether the response contained meaningful data
        - response_type: rough classification of the response content
        - data_preview: first 200 chars of stringified body for evidence
    """
    has_data = False
    response_type = "empty"
    data_preview = ""

    if body is not None:
        body_str = json.dumps(body) if not isinstance(body, str) else body

        if len(body_str) > 2:  # More than just {} or []
            has_data = True
            data_preview = body_str[:200]

            if isinstance(body, dict):
                if "data" in body or "status" in body:
                    response_type = "json_with_data"
                elif "error" in body or "message" in body:
                    response_type = "error_response"
                else:
                    response_type = "json_object"
            elif isinstance(body, list):
                response_type = f"json_array({len(body)} items)"
            else:
                response_type = "text"

    if status in (401, 403):
        response_type = "access_denied"
        has_data = False
    elif status == 404:
        response_type = "not_found"
        has_data = False
    elif status >= 500:
        response_type = "server_error"

    return {
        "has_data": has_data,
        "response_type": response_type,
        "data_preview": data_preview,
    }


class AccessMap:
    """
    Runtime permission matrix built from observed network traffic.

    Structure:
        _map[role][endpoint][method] = {
            "status": 200,
            "response_type": "json_with_data",
            "has_data": True,
            "data_preview": '{"id":1,"email":"admin@..."}',
            "iteration": 5,
            "timestamp": "2026-03-24T...",
            "raw_url": "http://localhost:3000/api/Users/1",
        }

    Multiple observations for the same role+endpoint+method will keep
    the most recent one (last-write-wins).
    """

    def __init__(self):
        self._map: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
        self._all_endpoints: Set[str] = set()
        self._all_roles: Set[str] = set()

    # ── Core update method ──────────────────────────────────────────

    def update_from_traffic(
        self,
        role: str,
        traffic: List[Dict[str, Any]],
        iteration: int = 0,
    ) -> int:
        """
        Process captured network traffic and update the map.

        Args:
            role:       The role that was active when this traffic was captured.
            traffic:    List of request/response dicts from NetworkInterceptor.
            iteration:  Current orchestrator iteration number.

        Returns:
            Number of new or updated entries added.
        """
        updated = 0
        self._all_roles.add(role)

        for record in traffic:
            url = record.get("url", "")
            method = record.get("method", "")
            status = record.get("status")

            # Skip non-API traffic and static assets
            if not _is_api_call(url) or _should_ignore(url):
                continue

            if status is None:
                continue  # Response hasn't arrived yet

            endpoint = _normalize_endpoint(url)
            self._all_endpoints.add(endpoint)

            # Classify the response
            classification = _classify_response(
                status, record.get("response_body")
            )

            # Initialize nested dicts
            if role not in self._map:
                self._map[role] = {}
            if endpoint not in self._map[role]:
                self._map[role][endpoint] = {}

            self._map[role][endpoint][method] = {
                "status": status,
                "response_type": classification["response_type"],
                "has_data": classification["has_data"],
                "data_preview": classification["data_preview"],
                "iteration": iteration,
                "timestamp": datetime.now().isoformat(),
                "raw_url": url,
            }
            updated += 1

        if updated:
            logger.info(
                "Access Map updated: role=%s, %d entries added/updated, "
                "total endpoints=%d, total roles=%d",
                role, updated, len(self._all_endpoints), len(self._all_roles),
            )

        return updated

    # ── Query methods ───────────────────────────────────────────────

    def get_untested_endpoints(self, role: str) -> List[Tuple[str, str]]:
        """
        Find endpoints that OTHER roles have accessed but this role hasn't.

        This is the key method for cross-role testing — it tells Strategy
        "admin can reach these endpoints, now try them as jim."

        Returns:
            List of (endpoint, method) tuples not yet tested for this role.
        """
        tested_by_role = set()
        if role in self._map:
            for endpoint, methods in self._map[role].items():
                for method in methods:
                    tested_by_role.add((endpoint, method))

        all_observed = set()
        for r, endpoints in self._map.items():
            for endpoint, methods in endpoints.items():
                for method in methods:
                    all_observed.add((endpoint, method))

        untested = all_observed - tested_by_role
        return sorted(untested)

    def get_potential_violations(self) -> List[Dict[str, Any]]:
        """
        Find endpoints where a lower-privilege role got the same access
        as a higher-privilege role (potential RBAC violations).

        Returns:
            List of dicts describing potential violations for the Analyzer.
        """
        violations = []

        for endpoint in self._all_endpoints:
            for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                # Collect all roles that accessed this endpoint+method
                role_results = {}
                for role in self._all_roles:
                    if (role in self._map and
                        endpoint in self._map[role] and
                        method in self._map[role][endpoint]):
                        entry = self._map[role][endpoint][method]
                        role_results[role] = entry

                # If multiple roles accessed it, check for mismatches
                if len(role_results) >= 2:
                    statuses = {r: e["status"] for r, e in role_results.items()}
                    # Flag if a non-admin role got 200 on the same endpoint as admin
                    admin_status = statuses.get("admin")
                    if admin_status == 200:
                        for role, status in statuses.items():
                            if role != "admin" and status == 200:
                                violations.append({
                                    "endpoint": endpoint,
                                    "method": method,
                                    "admin_status": admin_status,
                                    "role": role,
                                    "role_status": status,
                                    "admin_response_type": role_results["admin"]["response_type"],
                                    "role_response_type": role_results[role]["response_type"],
                                })

        return violations

    # ── Output methods ──────────────────────────────────────────────

    def summarize_for_strategy(self) -> str:
        """
        Format the access map as a readable text block for the Strategy Agent's
        LLM prompt. Focuses on what's been observed and what gaps remain.
        """
        if not self._map:
            return "(empty — no access data collected yet)"

        lines = []

        # Per-role summary
        for role in sorted(self._all_roles):
            endpoints = self._map.get(role, {})
            lines.append(f"  {role} ({len(endpoints)} endpoints observed):")

            for endpoint in sorted(endpoints.keys()):
                methods = endpoints[endpoint]
                for method, entry in sorted(methods.items()):
                    status = entry["status"]
                    rtype = entry["response_type"]
                    has_data = entry["has_data"]

                    # Compact one-line summary
                    data_flag = " [HAS DATA]" if has_data else ""
                    lines.append(
                        f"    {method} {endpoint} → {status} ({rtype}){data_flag}"
                    )
            lines.append("")

        # Cross-role gaps
        for role in sorted(self._all_roles):
            untested = self.get_untested_endpoints(role)
            if untested:
                lines.append(f"  UNTESTED for {role}: {len(untested)} endpoint(s)")
                for ep, method in untested[:10]:  # Cap to avoid huge prompts
                    lines.append(f"    → {method} {ep}")
                if len(untested) > 10:
                    lines.append(f"    ... and {len(untested) - 10} more")
                lines.append("")

        # Potential violations detected
        violations = self.get_potential_violations()
        if violations:
            lines.append(f"  POTENTIAL VIOLATIONS: {len(violations)}")
            for v in violations:
                lines.append(
                    f"    {v['method']} {v['endpoint']}: "
                    f"admin→{v['admin_status']} vs {v['role']}→{v['role_status']}"
                )
            lines.append("")

        return "\n".join(lines)

    def to_permission_matrix(self) -> Dict[str, Any]:
        """
        Export as a permission matrix JSON — one of the project deliverables.

        Format:
        {
            "endpoints": ["/api/Users", "/api/Users/{id}", ...],
            "roles": ["admin", "jim", "bender"],
            "matrix": {
                "/api/Users": {
                    "GET": {
                        "admin": {"status": 200, "has_data": true},
                        "jim": {"status": 200, "has_data": true},
                        "bender": {"status": 403, "has_data": false}
                    }
                }
            },
            "potential_violations": [...]
        }
        """
        matrix = {}

        for endpoint in sorted(self._all_endpoints):
            matrix[endpoint] = {}

            # Collect all methods observed for this endpoint
            all_methods = set()
            for role_data in self._map.values():
                if endpoint in role_data:
                    all_methods.update(role_data[endpoint].keys())

            for method in sorted(all_methods):
                matrix[endpoint][method] = {}
                for role in sorted(self._all_roles):
                    if (role in self._map and
                        endpoint in self._map[role] and
                        method in self._map[role][endpoint]):
                        entry = self._map[role][endpoint][method]
                        matrix[endpoint][method][role] = {
                            "status": entry["status"],
                            "has_data": entry["has_data"],
                            "response_type": entry["response_type"],
                        }
                    else:
                        matrix[endpoint][method][role] = None  # Not tested

        return {
            "endpoints": sorted(self._all_endpoints),
            "roles": sorted(self._all_roles),
            "matrix": matrix,
            "potential_violations": self.get_potential_violations(),
            "generated_at": datetime.now().isoformat(),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export raw map for serialization (e.g., saving in reports)."""
        return {
            "map": self._map,
            "all_endpoints": sorted(self._all_endpoints),
            "all_roles": sorted(self._all_roles),
        }

    def __len__(self) -> int:
        """Total number of role+endpoint+method observations."""
        count = 0
        for role_data in self._map.values():
            for endpoint_data in role_data.values():
                count += len(endpoint_data)
        return count

    def __repr__(self) -> str:
        return (
            f"AccessMap(roles={len(self._all_roles)}, "
            f"endpoints={len(self._all_endpoints)}, "
            f"observations={len(self)})"
        )
