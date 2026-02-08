"""
KasmVNC Plus E2E — API Tests (Groups 1, 2, 4, 5)
=================================================
Tests all HTTP-level endpoints using the `requests` library.
Runs BEFORE browser tests to validate infrastructure.

Usage:
    source tests/.venv/bin/activate
    pytest tests/test_api.py -v --tb=short
"""
import json
import os
import pytest
import requests
from urllib.parse import urlparse, parse_qs
from conftest import BASE_URL, KEYCLOAK_URL

# ═══════════════════════════════════════════════════════════════════════════════
# Group 1: OAuth SSO Flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestGroup1_OAuthSSOFlow:
    """Verify all OAuth/OIDC endpoints respond correctly without auth."""

    def test_1_1_landing_page_status(self, api_session, results_log):
        """GET / → 200"""
        r = api_session.get(f"{BASE_URL}/", allow_redirects=False, timeout=10)
        passed = r.status_code == 200
        results_log.record("1.1", "Group 1: OAuth SSO Flow",
                           "Landing page returns 200", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert r.status_code == 200

    def test_1_1b_landing_page_has_stitch_ui(self, api_session, results_log):
        """GET / → body contains 'KasmVNC'"""
        r = api_session.get(f"{BASE_URL}/", timeout=10)
        has_branding = "KasmVNC" in r.text
        results_log.record("1.1b", "Group 1: OAuth SSO Flow",
                           "Landing page contains KasmVNC branding", "PASS" if has_branding else "FAIL",
                           f"Body length: {len(r.text)}")
        assert has_branding, f"Body does not contain 'KasmVNC': {r.text[:200]}"

    def test_1_1c_landing_page_has_sso_button(self, api_session, results_log):
        """GET / → body contains 'Sign in with SSO' or '/auth/login'"""
        r = api_session.get(f"{BASE_URL}/", timeout=10)
        has_sso = "Sign in with SSO" in r.text or "/auth/login" in r.text
        results_log.record("1.1c", "Group 1: OAuth SSO Flow",
                           "Landing page has SSO button/link", "PASS" if has_sso else "FAIL")
        assert has_sso

    def test_1_2_sso_redirect_to_keycloak(self, api_session, results_log):
        """GET /auth/login → 307 redirect to Keycloak"""
        r = api_session.get(f"{BASE_URL}/auth/login", allow_redirects=False, timeout=10)
        location = r.headers.get("location", "")
        is_redirect = r.status_code in (302, 307)
        to_keycloak = "realms/test/protocol/openid-connect/auth" in location
        passed = is_redirect and to_keycloak
        results_log.record("1.2", "Group 1: OAuth SSO Flow",
                           "SSO redirects to Keycloak", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code} → {location[:80]}...")
        assert passed, f"Expected redirect to Keycloak, got HTTP {r.status_code} → {location}"

    def test_1_2b_pkce_s256_in_redirect(self, api_session, results_log):
        """GET /auth/login → redirect URL contains code_challenge_method=S256"""
        r = api_session.get(f"{BASE_URL}/auth/login", allow_redirects=False, timeout=10)
        location = r.headers.get("location", "")
        has_pkce = "code_challenge_method=S256" in location
        results_log.record("1.2b", "Group 1: OAuth SSO Flow",
                           "PKCE S256 in redirect URL", "PASS" if has_pkce else "FAIL",
                           f"code_challenge_method={'found' if has_pkce else 'missing'}")
        assert has_pkce, f"No code_challenge_method=S256 in: {location}"

    def test_1_3_callback_rejects_missing_code(self, api_session, results_log):
        """GET /auth/callback (no params) → 400 (OIDC error)"""
        r = api_session.get(f"{BASE_URL}/auth/callback", allow_redirects=False, timeout=10)
        # Callback with no code/state → Axum returns 422 (missing query) or 400 (OIDC error)
        passed = r.status_code in (400, 422, 500)
        results_log.record("1.3", "Group 1: OAuth SSO Flow",
                           "Callback rejects missing code", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert passed, f"Expected 400/422/500, got HTTP {r.status_code}"

    def test_1_4_session_api_unauthenticated(self, api_session, results_log):
        """GET /api/session → {authenticated: false}"""
        r = api_session.get(f"{BASE_URL}/api/session", timeout=10)
        data = r.json()
        passed = r.status_code == 200 and data.get("authenticated") is False
        results_log.record("1.4", "Group 1: OAuth SSO Flow",
                           "Session API returns unauthenticated", "PASS" if passed else "FAIL",
                           json.dumps(data))
        assert passed, f"Expected authenticated=false, got: {data}"

    def test_1_5_logout_redirects_to_keycloak(self, api_session, results_log):
        """GET /auth/logout → 307 redirect to Keycloak logout"""
        r = api_session.get(f"{BASE_URL}/auth/logout", allow_redirects=False, timeout=10)
        location = r.headers.get("location", "")
        is_redirect = r.status_code in (302, 307)
        to_keycloak = "openid-connect/logout" in location
        passed = is_redirect and to_keycloak
        results_log.record("1.5", "Group 1: OAuth SSO Flow",
                           "Logout redirects to Keycloak", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code} → {location[:80]}")
        assert passed, f"Expected redirect to Keycloak logout, got HTTP {r.status_code}"


# ═══════════════════════════════════════════════════════════════════════════════
# Group 2: Admin Dashboard Auth Guards
# ═══════════════════════════════════════════════════════════════════════════════


class TestGroup2_AdminAuthGuards:
    """Verify all admin pages return 401 when not authenticated."""

    ADMIN_PAGES = [
        ("2.1", "/admin", "Dashboard"),
        ("2.2", "/admin/sessions", "Sessions"),
        ("2.3", "/admin/users", "Users"),
        ("2.4", "/admin/policies", "Policies"),
        ("2.5", "/admin/recordings", "Recordings"),
        ("2.6", "/admin/audit", "Audit"),
        ("2.7", "/admin/images", "Images"),
        ("2.8", "/admin/settings", "Settings"),
    ]

    @pytest.mark.parametrize("test_id,path,name", ADMIN_PAGES)
    def test_admin_page_requires_auth(self, api_session, results_log, test_id, path, name):
        """GET /admin/* without auth → 401"""
        r = api_session.get(f"{BASE_URL}{path}", allow_redirects=False, timeout=10)
        passed = r.status_code == 401
        results_log.record(test_id, "Group 2: Admin Auth Guards",
                           f"{name} page requires auth", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert r.status_code == 401, f"Expected 401 for {path}, got {r.status_code}"

    def test_2_9_nonexistent_admin_page(self, api_session, results_log):
        """GET /admin/nonexistent → 401 (auth checked before page lookup)"""
        r = api_session.get(f"{BASE_URL}/admin/nonexistent", allow_redirects=False, timeout=10)
        # Auth guard fires first → 401 regardless of page existence
        passed = r.status_code == 401
        results_log.record("2.9", "Group 2: Admin Auth Guards",
                           "Nonexistent admin page returns 401 (auth first)", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert passed, f"Expected 401, got {r.status_code}"

    def test_2_10_path_traversal_blocked(self, api_session, results_log):
        """GET /admin/../../etc/passwd → 400 (sanitizer rejects)"""
        r = api_session.get(f"{BASE_URL}/admin/..%2F..%2Fetc%2Fpasswd",
                           allow_redirects=False, timeout=10)
        # Route matches /admin/{page} — page = "../../etc/passwd"
        # Sanitizer only allows alphanumeric + hyphens → 401 (auth first) or 400
        passed = r.status_code in (400, 401, 404)
        results_log.record("2.10", "Group 2: Admin Auth Guards",
                           "Path traversal blocked", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert passed, f"Expected 400/401/404, got {r.status_code}"


# ═══════════════════════════════════════════════════════════════════════════════
# Group 5: Health Probes & Security
# ═══════════════════════════════════════════════════════════════════════════════


class TestGroup5_HealthProbes:
    """Verify health probes and security headers."""

    def test_5_1_liveness_probe(self, api_session, results_log):
        """GET /healthz → 200"""
        r = api_session.get(f"{BASE_URL}/healthz", timeout=10)
        passed = r.status_code == 200
        results_log.record("5.1", "Group 5: Health Probes & Security",
                           "Liveness probe returns 200", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert r.status_code == 200

    def test_5_2_readiness_probe(self, api_session, results_log):
        """GET /readyz → 503 (pre-VNC, no /tmp/sso_ready) or 200 (post-SSO)"""
        r = api_session.get(f"{BASE_URL}/readyz", timeout=10)
        # Before SSO login, sso_ready doesn't exist → 503
        # After SSO login, sso_ready exists → 200
        passed = r.status_code in (200, 503)
        results_log.record("5.2", "Group 5: Health Probes & Security",
                           "Readiness probe returns valid state", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert passed, f"Expected 200 or 503, got {r.status_code}"

    def test_5_3_reverse_proxy_unauth(self, api_session, results_log):
        """GET /vnc/ without auth → 401 (NotAuthenticated)"""
        r = api_session.get(f"{BASE_URL}/vnc/", allow_redirects=False, timeout=10)
        passed = r.status_code == 401
        results_log.record("5.3", "Group 5: Health Probes & Security",
                           "Reverse proxy rejects unauthenticated", "PASS" if passed else "FAIL",
                           f"HTTP {r.status_code}")
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"

    def test_5_4_cors_headers_present(self, api_session, results_log):
        """OPTIONS / → has access-control headers (permissive CORS layer)"""
        r = api_session.options(f"{BASE_URL}/", timeout=10)
        cors_header = r.headers.get("access-control-allow-origin", "")
        passed = cors_header != ""
        results_log.record("5.4", "Group 5: Health Probes & Security",
                           "CORS headers present", "PASS" if passed else "FAIL",
                           f"access-control-allow-origin: {cors_header or 'MISSING'}")
        assert passed, "No CORS headers in response"
