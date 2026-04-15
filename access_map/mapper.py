"""
Access Map Mapper — builds and maintains a structured map of discovered
endpoints and their per-role access results.

Consumes raw network traffic from NetworkInterceptor and page navigations
from the Orchestrator, normalizes paths, and accumulates a permission
matrix keyed by (method, path_template) → {role: status_code}.

The Access Map is read by the Strategy Agent to decide what to re-test
under different roles. The Mapper itself never triggers actions.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Path normalisation helpers ──────────────────────────────────────

_NUMERIC_ID = re.compile(r"/(\d+)(?=/|$)")
_UUID = re.compile(
    r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$)"
)
_OBJECT_ID = re.compile(r"/([0-9a-fA-F]{24})(?=/|$)")


def normalise_path(path: str) -> str:
    path = path.split("?")[0]
    path = _UUID.sub(r"/{id}", path)
    path = _OBJECT_ID.sub(r"/{id}", path)
    path = _NUMERIC_ID.sub(r"/{id}", path)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


# ── Data structures ─────────────────────────────────────────────────

@dataclass
class EndpointRecord:
    method: str
    path_template: str
    role_results: Dict[str, List[int]] = field(default_factory=dict)
    raw_paths: Dict[str, Set[str]] = field(default_factory=lambda: {})
    role_response_sizes: Dict[str, List[int]] = field(default_factory=dict)
    first_seen_iteration: Optional[int] = None

    def roles_tested(self) -> List[str]:
        return list(self.role_results.keys())

    def latest_status(self, role: str) -> Optional[int]:
        codes = self.role_results.get(role)
        return codes[-1] if codes else None

    def is_accessible_by(self, role: str) -> bool:
        return any(200 <= c < 300 for c in self.role_results.get(role, []))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "path_template": self.path_template,
            "role_results": {r: codes for r, codes in self.role_results.items()},
            "role_response_sizes": dict(self.role_response_sizes),
            "first_seen_iteration": self.first_seen_iteration,
        }
    


# ── Access Map ──────────────────────────────────────────────────────

class AccessMap:
    def __init__(self):
        self._map: Dict[Tuple[str, str], EndpointRecord] = {}
        self._known_roles: Set[str] = set()
        # Track which IDOR probes have already been executed
        self._idor_tested: Set[Tuple[str, str, str]] = set()  # (role, method, url)

    # ── IDOR tracking ───────────────────────────────────────────────

    def mark_idor_tested(self, role: str, method: str, url: str) -> None:
        """Mark an IDOR probe as completed so it won't be suggested again."""
        self._idor_tested.add((role, method, url))

    def is_idor_tested(self, role: str, method: str, url: str) -> bool:
        """Check if this specific IDOR probe has already been done."""
        return (role, method, url) in self._idor_tested

    def get_pending_idor_targets(self, current_role: str, base_url: str = "") -> List[Dict[str, Any]]:
        """
        Return concrete IDOR test actions for the current role.

        Scans all endpoints with {id} in the template, finds IDs accessed
        by OTHER roles, and returns any that haven't been tested yet by
        the current role.
        """
        targets = []
        for key, rec in self._map.items():
            if "{id}" not in rec.path_template:
                continue
            # Only consider endpoints where at least one role got 2xx
            for role, raw_paths in rec.raw_paths.items():
                if role == current_role:
                    continue
                if not rec.is_accessible_by(role):
                    continue
                for path in raw_paths:
                    match = re.search(r'/(\d+)(?:/|$)', path)
                    if not match:
                        continue
                    actual_id = match.group(1)
                    url = f"{base_url.rstrip('/')}{rec.path_template.replace('{id}', actual_id)}"
                    if self.is_idor_tested(current_role, rec.method, url):
                        continue
                    targets.append({
                        "method": rec.method,
                        "template": rec.path_template,
                        "id": actual_id,
                        "url": url,
                        "tested_by": role,
                        "status": rec.latest_status(role),
                    })
        return targets

    # ── Recording ───────────────────────────────────────────────────

    def record(
        self,
        method: str,
        raw_path: str,
        status_code: int,
        role: str,
        iteration: int,
        response_size: Optional[int] = None,
    ) -> None:
        method = method.upper()
        template = normalise_path(raw_path)
        key = (method, template)

        self._known_roles.add(role)

        if key not in self._map:
            self._map[key] = EndpointRecord(
                method=method,
                path_template=template,
                first_seen_iteration=iteration,
            )

        rec = self._map[key]
        rec.role_results.setdefault(role, []).append(status_code)
        rec.raw_paths.setdefault(role, set()).add(raw_path)

        if response_size is not None:
            rec.role_response_sizes.setdefault(role, []).append(response_size)

        logger.debug(
            "AccessMap: %s %s [%s] → %d (iter %d)",
            method, template, role, status_code, iteration,
        )

    def record_page_navigation(
        self,
        url: str,
        status_code: int,
        role: str,
        iteration: int,
    ) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path or "/"

        if parsed.fragment:
            path = f"{path}#{parsed.fragment}" if path != "/" else f"/#{parsed.fragment}"

        self.record(
            method="GET",
            raw_path=path,
            status_code=status_code,
            role=role,
            iteration=iteration,
        )

    def record_traffic(
        self,
        traffic: List[Dict[str, Any]],
        role: str,
        iteration: int,
        base_url: str = "",
    ) -> int:
        count = 0
        for entry in traffic:
            method = entry.get("method", "GET").upper()
            url = entry.get("url", "")
            status = entry.get("status") or entry.get("status_code") or 0

            if not url or not status:
                continue
            if not url.startswith("http"):
                continue

            path = url
            if base_url and url.startswith(base_url):
                path = url[len(base_url):]
                if not path.startswith("/"):
                    path = "/" + path

            if _is_static_asset(path):
                continue

            resp_size = entry.get("response_size") or entry.get("response_body_length")
            self.record(method, path, status, role, iteration, resp_size)
            count += 1

        logger.info(
            "AccessMap: recorded %d entries from traffic (role=%s, iter=%d)",
            count, role, iteration,
        )
        return count

    # ── Querying ────────────────────────────────────────────────────

    @property
    def known_roles(self) -> List[str]:
        return sorted(self._known_roles)

    @property
    def endpoints(self) -> List[EndpointRecord]:
        return list(self._map.values())

    def get(self, method: str, path_template: str) -> Optional[EndpointRecord]:
        return self._map.get((method.upper(), path_template))

    def get_untested_roles(self, method: str, path_template: str) -> List[str]:
        rec = self.get(method, path_template)
        if not rec:
            return list(self._known_roles)
        return [r for r in self._known_roles if r not in rec.role_results]

    def get_endpoints_for_role(self, role: str) -> List[EndpointRecord]:
        return [rec for rec in self._map.values() if role in rec.role_results]

    def get_potential_issues(self) -> List[Dict[str, Any]]:
        issues = []
        for key, rec in self._map.items():
            accessible_roles = [r for r in rec.role_results if rec.is_accessible_by(r)]
            if len(accessible_roles) > 1:
                issues.append({
                    "type": "multi_role_access",
                    "method": rec.method,
                    "path": rec.path_template,
                    "accessible_roles": accessible_roles,
                    "severity_hint": "review",
                })
            if len(rec.roles_tested()) == 1 and len(self._known_roles) > 1:
                issues.append({
                    "type": "untested_cross_role",
                    "method": rec.method,
                    "path": rec.path_template,
                    "tested_roles": rec.roles_tested(),
                    "untested_roles": self.get_untested_roles(rec.method, rec.path_template),
                    "severity_hint": "needs_testing",
                })
        return issues

    # ── Summarisation for Strategy ──────────────────────────────────

    def summarise_for_strategy(self, max_entries: int = 50, current_role: str = "", base_url: str = "") -> str:
        if not self._map:
            return "ACCESS MAP: Empty — no endpoints discovered yet."

        lines = [
            "=== ACCESS MAP ===",
            f"Known roles: {', '.join(self.known_roles)}",
            f"Total endpoints: {len(self._map)}",
            "",
        ]

        # ── IDOR TARGETS (highest priority) ──
        if current_role:
            idor_targets = self.get_pending_idor_targets(current_role, base_url)
            if idor_targets:
                # Deduplicate by (method, url)
                seen = set()
                deduped = []
                for t in idor_targets:
                    key = (t["method"], t["url"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(t)

                lines.append(f"=== IDOR TARGETS — TEST THESE NOW ({len(deduped)}) ===")
                lines.append(
                    "These endpoints have numeric IDs accessed by another role."
                )
                lines.append(
                    "Use test_access to try each URL as the current role."
                )
                lines.append("")
                for t in deduped:
                    lines.append(
                        f"  → test_access {t['method']} {t['url']}  "
                        f"({t['tested_by']} got {t['status']})"
                    )
                lines.append("")

        # ── Potential issues ──
        issues = self.get_potential_issues()
        needs_testing = [i for i in issues if i["type"] == "untested_cross_role"]
        multi_access = [i for i in issues if i["type"] == "multi_role_access"]

        if needs_testing:
            lines.append(f"--- NEEDS CROSS-ROLE TESTING ({len(needs_testing)}) ---")
            for issue in needs_testing[:15]:
                lines.append(
                    f"  {issue['method']} {issue['path']}  "
                    f"tested=[{','.join(issue['tested_roles'])}]  "
                    f"untested=[{','.join(issue['untested_roles'])}]"
                )
            lines.append("")

        if multi_access:
            lines.append(f"--- MULTIPLE ROLES HAVE ACCESS ({len(multi_access)}) ---")
            for issue in multi_access[:15]:
                lines.append(
                    f"  {issue['method']} {issue['path']}  "
                    f"accessible=[{','.join(issue['accessible_roles'])}]"
                )
            lines.append("")

        # ── Full map ──
        lines.append("--- FULL MAP ---")
        sorted_recs = sorted(
            self._map.values(),
            key=lambda r: r.first_seen_iteration or 0,
            reverse=True,
        )
        for rec in sorted_recs[:max_entries]:
            role_str = "  ".join(
                f"{role}={rec.latest_status(role)}"
                for role in sorted(rec.role_results.keys())
            )
            lines.append(f"  {rec.method} {rec.path_template}  |  {role_str}")

        if len(self._map) > max_entries:
            lines.append(f"  ... and {len(self._map) - max_entries} more")

        return "\n".join(lines)

    # ── Serialisation ───────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "known_roles": self.known_roles,
            "total_endpoints": len(self._map),
            "endpoints": [rec.to_dict() for rec in self._map.values()],
        }
    
    def dump_human_readable(self, current_role: str = "", base_url: str = "") -> str:
        """
        Return a human-readable summary of everything the agent has learned.
        Call this any time you want to see the full state of the access map.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            f"║  ARGUS ACCESS MAP  —  {now}",
            f"║  {len(self._map)} endpoints  |  roles: {', '.join(self.known_roles)}",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
        ]

        # ── Section 1: IDOR targets still pending ──────────────────────
        if current_role:
            targets = self.get_pending_idor_targets(current_role, base_url)
            # Deduplicate by (method, url)
            seen = set()
            deduped = []
            for t in targets:
                k = (t["method"], t["url"])
                if k not in seen:
                    seen.add(k)
                    deduped.append(t)

            if deduped:
                lines.append(f"IDOR TARGETS — {current_role} should probe these ({len(deduped)})")
                lines.append("  " + "─" * 60)
                for t in deduped:
                    lines.append(
                        f"  → {t['method']:<6} {t['url']}"
                    )
                    lines.append(
                        f"           tested_by={t['tested_by']}  "
                        f"their_status={t['status']}"
                    )
                lines.append("")
            else:
                lines.append(f"No pending IDOR targets for role '{current_role}'")
                lines.append("")

        # ── Section 2: Completed IDOR probes ───────────────────────────
        if self._idor_tested:
            lines.append(f"COMPLETED IDOR PROBES ({len(self._idor_tested)})")
            lines.append("  " + "─" * 60)
            for (role, method, url) in sorted(self._idor_tested):
                lines.append(f"{role:<10} {method:<6} {url}")
            lines.append("")

        # ── Section 3: Endpoints needing cross-role testing ────────────
        issues = self.get_potential_issues()
        needs_testing = [i for i in issues if i["type"] == "untested_cross_role"]
        if needs_testing:
            lines.append(f"NEEDS CROSS-ROLE TESTING ({len(needs_testing)})")
            lines.append("  " + "─" * 60)
            for issue in needs_testing:
                tested   = ", ".join(issue["tested_roles"])
                untested = ", ".join(issue["untested_roles"])
                lines.append(
                    f"  {issue['method']:<6} {issue['path']}"
                )
                lines.append(
                    f"  tested=[{tested}]  untested=[{untested}]"
                )
            lines.append("")

        # ── Section 4: Full endpoint matrix ────────────────────────────
        lines.append("  FULL ENDPOINT MATRIX")
        lines.append("  " + "─" * 60)
        lines.append(
            f"  {'METHOD':<6}  {'PATH TEMPLATE':<45}  "
            + "  ".join(f"{r:<12}" for r in self.known_roles)
        )
        lines.append("  " + "─" * 60)

        sorted_recs = sorted(
            self._map.values(),
            key=lambda r: (r.path_template, r.method),
        )

        for rec in sorted_recs:
            role_cols = []
            for role in self.known_roles:
                status = rec.latest_status(role)
                if status is None:
                    cell = "—"
                elif 200 <= status < 300:
                    cell = f"{status}"   # accessible
                elif status in (401, 403):
                    cell = f"{status}"   # blocked (expected)
                else:
                    cell = str(status)
                role_cols.append(f"{cell:<12}")

            # Flag rows where 2+ roles got 2xx — potential IDOR
            accessible = [r for r in self.known_roles if rec.is_accessible_by(r)]
            flag = "  [!!] MULTI-ROLE" if len(accessible) > 1 else ""

            lines.append(
                f"  {rec.method:<6}  {rec.path_template:<45}  "
                + "  ".join(role_cols)
                + flag
            )

            # Show concrete IDs seen per role (helpful for IDOR targeting)
            for role, paths in rec.raw_paths.items():
                ids = set()
                for p in paths:
                    m = re.findall(r'/(\d+)(?:/|$)', p)
                    ids.update(m)
                if ids:
                    lines.append(
                        f"  {'':6}  {'':45}  "
                        f"{role} saw ids: {', '.join(sorted(ids, key=int))}"
                    )

        lines.append("")
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._map)

    def __repr__(self) -> str:
        return f"AccessMap(endpoints={len(self._map)}, roles={self.known_roles})"


# ── Helpers ─────────────────────────────────────────────────────────

_STATIC_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
})

_STATIC_PREFIXES = ("/assets/", "/node_modules/", "/socket.io/")


def _is_static_asset(path: str) -> bool:
    lower = path.lower().split("?")[0]
    if any(lower.endswith(ext) for ext in _STATIC_EXTENSIONS):
        return True
    if any(lower.startswith(prefix) for prefix in _STATIC_PREFIXES):
        return True
    return False

