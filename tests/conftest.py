"""
KasmVNC Plus E2E Test Suite — Shared Configuration & Fixtures
=============================================================
Provides pytest fixtures for:
  - Timestamped output directory (PT timezone, AM/PM)
  - Shared requests session with cookie jar
  - Shared Playwright browser context
  - Configuration constants
"""
import os
import json
import pytest
from datetime import datetime
from zoneinfo import ZoneInfo

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_URL = os.getenv("KASMVNC_URL", "http://localhost:8888")
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8089")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "test")
KEYCLOAK_USER = os.getenv("KEYCLOAK_USER", "testuser")
KEYCLOAK_PASS = os.getenv("KEYCLOAK_PASS", "password")
SESSION_CONTROLLER_URL = os.getenv("SESSION_CONTROLLER_URL", "http://localhost:9090")

# ─── Timestamped Output ─────────────────────────────────────────────────────

def get_timestamp_pt():
    """Return current time in Pacific Time with AM/PM format."""
    pt = ZoneInfo("America/Los_Angeles")
    return datetime.now(pt).strftime("%Y-%m-%d_%I-%M-%S_%p_PT")


@pytest.fixture(scope="session")
def output_dir():
    """Create a timestamped output directory for test evidence."""
    ts = get_timestamp_pt()
    path = os.path.join(os.path.dirname(__file__), "output", ts)
    os.makedirs(path, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def results_log(output_dir):
    """JSON results accumulator — writes final results at end of session."""
    results = []

    class ResultsLog:
        def record(self, test_id, group, description, status, details=""):
            entry = {
                "test_id": test_id,
                "group": group,
                "description": description,
                "status": status,
                "details": details,
                "timestamp": get_timestamp_pt(),
            }
            results.append(entry)

        def entries(self):
            return results

    log = ResultsLog()
    yield log

    # Write final results JSON
    results_file = os.path.join(output_dir, "results.json")
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    # Write human-readable summary
    summary_file = os.path.join(output_dir, "summary.txt")
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    total = len(results)

    with open(summary_file, "w") as f:
        f.write(f"KasmVNC Plus E2E Test Results\n")
        f.write(f"{'=' * 60}\n")
        f.write(f"Run: {get_timestamp_pt()}\n")
        f.write(f"Base URL: {BASE_URL}\n\n")
        f.write(f"TOTAL: {total}  |  PASS: {passed}  |  FAIL: {failed}  |  SKIP: {skipped}\n")
        f.write(f"{'=' * 60}\n\n")

        current_group = None
        for r in results:
            if r["group"] != current_group:
                current_group = r["group"]
                f.write(f"\n── {current_group} ──\n")
            icon = "✅" if r["status"] == "PASS" else ("❌" if r["status"] == "FAIL" else "⏭️")
            f.write(f"  {icon} {r['test_id']}: {r['description']}")
            if r["details"]:
                f.write(f"  ({r['details']})")
            f.write("\n")


# ─── Requests Session (API Tests) ───────────────────────────────────────────

@pytest.fixture(scope="session")
def api_session():
    """Shared requests.Session with cookie persistence for API tests."""
    import requests
    session = requests.Session()
    session.headers.update({"User-Agent": "KasmVNC-E2E-Tests/1.0"})
    yield session
    session.close()


# ─── Playwright Fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def browser_context_args():
    """Configure Playwright browser context."""
    return {
        "ignore_https_errors": True,
        "viewport": {"width": 1280, "height": 720},
    }
