"""
Static knowledge documents seeded into the RAG knowledge base.

These are loaded once on first startup and never change between runs.
They give the Strategy Agent grounding in:
  - OWASP broken access control patterns
  - General IDOR / RBAC testing heuristics

Each document is a dict with:
  - id:       unique stable identifier (used to avoid re-inserting on restart)
  - text:     the content that gets embedded and retrieved
  - metadata: structured tags for filtered retrieval (category, vuln_type, etc.)
"""

from typing import Any, Dict, List

# ── OWASP Broken Access Control patterns ────────────────────────────

OWASP_DOCS: List[Dict[str, Any]] = [
    {
        "id": "owasp_bac_overview",
        "text": (
            "Broken Access Control (OWASP A01:2025) occurs when users can act outside their "
            "intended permissions. Common patterns include: bypassing access control checks by "
            "modifying the URL, internal application state, or HTML page; changing the primary "
            "key to another user's record to view or edit their account; elevation of privilege "
            "by acting as a user without being logged in, or acting as an admin when logged in "
            "as a user; metadata manipulation such as replaying or tampering with a JWT access "
            "control token or a cookie to elevate privileges; CORS misconfiguration allowing "
            "API access from unauthorized origins; force browsing to authenticated pages as an "
            "unauthenticated user or to privileged pages as a standard user."
        ),
        "metadata": {"category": "owasp", "vuln_type": "general", "source": "OWASP Top 10 2025"},
    },
    {
        "id": "owasp_idor_pattern",
        "text": (
            "Insecure Direct Object Reference (IDOR) testing approach: Identify all endpoints "
            "that accept a resource identifier (numeric ID, UUID, username) in the URL path or "
            "query string. Examples: /api/orders/1234, /api/users/5/profile. "
            "Create two accounts (attacker and victim). As the victim, create a resource and "
            "note its ID. As the attacker, attempt to access or modify the victim's resource "
            "using their ID. A vulnerability exists if the server returns the victim's data "
            "with a 200 response. Also test: incrementing IDs sequentially, substituting "
            "another user's known ID, and using negative or zero values."
        ),
        "metadata": {"category": "owasp", "vuln_type": "IDOR", "source": "OWASP Testing Guide"},
    },
    {
        "id": "owasp_rbac_pattern",
        "text": (
            "Function-Level Access Control testing: Map all application functions — admin, "
            "user, and unauthenticated. For each privileged function, attempt access with a "
            "lower-privilege role. Key indicators of RBAC failure: an admin-only page returns "
            "HTTP 200 for a regular user; an API endpoint intended for admins returns data for "
            "a customer role; UI hides the button but the underlying API call still succeeds; "
            "a user can perform create/update/delete on resources they should only be able to "
            "read. Always test both the UI navigation AND the direct API call independently."
        ),
        "metadata": {"category": "owasp", "vuln_type": "RBAC", "source": "OWASP Testing Guide"},
    },
    {
        "id": "owasp_tenant_isolation",
        "text": (
            "Tenant Isolation testing in multi-user applications: Each user should only see "
            "their own data. Test by: logging in as User A, creating resources (orders, "
            "addresses, payment cards), logging out, logging in as User B, then attempting "
            "to access User A's resource IDs directly. A violation occurs when User B can "
            "read, modify, or delete User A's data. Common failure points: shared basket IDs, "
            "order history endpoints, address books, and payment card storage. Also test "
            "cross-tenant API calls where the tenant identifier is passed as a parameter "
            "rather than derived from the session token."
        ),
        "metadata": {"category": "owasp", "vuln_type": "Tenant Isolation", "source": "OWASP Testing Guide"},
    },
    {
        "id": "owasp_privilege_escalation",
        "text": (
            "Privilege escalation testing: Vertical escalation — a regular user gains admin "
            "capabilities. Horizontal escalation — a user accesses another user's data at the "
            "same privilege level. Test vectors: modify role or admin fields in API request "
            "bodies; tamper with JWT claims (change 'role': 'user' to 'role': 'admin'); "
            "replay an admin's captured request with a regular user's session token; attempt "
            "account takeover by manipulating password reset flows or profile update endpoints "
            "with another user's ID."
        ),
        "metadata": {"category": "owasp", "vuln_type": "Privilege Escalation", "source": "OWASP Testing Guide"},
    },
]

# ── Testing heuristics ───────────────────────────────────────────────

HEURISTIC_DOCS: List[Dict[str, Any]] = [
    {
        "id": "heuristic_id_manipulation",
        "text": (
            "ID manipulation heuristics for access control testing: When a numeric ID appears "
            "in a URL or response body, always test: (1) ID - 1 and ID + 1 to access adjacent "
            "records; (2) ID of a known other user (e.g., admin is usually ID 1); (3) ID = 0 "
            "or negative values for boundary testing; (4) Very large IDs to test for "
            "enumeration limits. When multiple IDs appear (e.g., userId=5&orderId=42), test "
            "substituting each independently. The most valuable tests combine a low-privilege "
            "session token with a high-privilege resource ID."
        ),
        "metadata": {"category": "heuristic", "vuln_type": "IDOR"},
    },
    {
        "id": "heuristic_http_status",
        "text": (
            "HTTP status code interpretation for access control testing: "
            "200 OK on a privileged endpoint = likely vulnerability, investigate response body. "
            "401 Unauthorized = authentication required, expected for unauthenticated access. "
            "403 Forbidden = authenticated but not authorized, correct behavior. "
            "404 Not Found on a known-to-exist resource = may indicate access control by "
            "obscurity rather than true enforcement (test with admin to confirm existence). "
            "500 Internal Server Error on an access-controlled endpoint = potential "
            "information disclosure or incomplete authorization check. "
            "302 Redirect to login = correct behavior for session-protected routes."
        ),
        "metadata": {"category": "heuristic", "vuln_type": "general"},
    },
    {
        "id": "heuristic_ui_api_mismatch",
        "text": (
            "UI/API mismatch testing: Many access control bugs occur when the UI hides a "
            "button or link for lower-privilege users, but the underlying API endpoint has "
            "no server-side authorization check. Testing approach: (1) As admin, identify "
            "all API calls made when performing privileged actions (capture network traffic). "
            "(2) Note the exact request: method, URL, headers, request body. (3) Replay the "
            "same request using a customer session token. (4) If the server returns 200 with "
            "the same data, the access control relies only on UI hiding — this is a "
            "function-level authorization failure."
        ),
        "metadata": {"category": "heuristic", "vuln_type": "RBAC"},
    },
    {
        "id": "heuristic_jwt_testing",
        "text": (
            "JWT and session token testing for privilege escalation: Many web applications "
            "use JWT tokens in the Authorization header as Bearer tokens. The token payload "
            "may contain user id, email, and role fields. Test: (1) Decode the JWT (base64) "
            "and inspect the payload claims. (2) Check if the token contains a 'role' or "
            "'admin' field. If so, attempt to modify it and re-sign (algorithm confusion "
            "attacks). (3) Test if the server accepts tokens signed with 'none' algorithm. "
            "(4) Capture an admin's token and replay requests with it while logged in as "
            "a regular user to confirm server-side role enforcement from the token."
        ),
        "metadata": {"category": "heuristic", "vuln_type": "Privilege Escalation"},
    },
]

# ── Combined export ──────────────────────────────────────────────────

ALL_STATIC_DOCUMENTS: List[Dict[str, Any]] = (
    OWASP_DOCS + HEURISTIC_DOCS
)