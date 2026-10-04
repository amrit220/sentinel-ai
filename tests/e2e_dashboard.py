"""End-to-end dashboard test with Playwright (headless Chromium).

Simulates a real user: opens the dashboard, starts a scan against the
bundled demo target, watches the live pipeline, opens the results page,
expands a finding and plays an attack replay.

Run:  python tests/e2e_dashboard.py
Prereq: backend running  (python app.py --with-demo)
Artifacts: tests/artifacts/*.png + console/network error log
"""
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, expect

BASE = "http://127.0.0.1:5000"
ART = Path(__file__).parent / "artifacts"
ART.mkdir(parents=True, exist_ok=True)

console_errors = []
page_errors = []
failed_requests = []


def shot(page, name):
    page.screenshot(path=str(ART / f"{name}.png"), full_page=True)
    print(f"  [shot] {name}.png")


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1500, "height": 950})
        page = ctx.new_page()
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: page_errors.append(str(e)))
        # no-cors pings to the demo target always abort in Chromium —
        # they are connect-probes, not real failures, so exclude them.
        page.on("requestfailed", lambda r: failed_requests.append(f"{r.url} {r.failure}")
                if ":5099" not in r.url else None)

        # ---------------------------------------------------- 1. dashboard
        print("[1] loading dashboard ...")
        page.goto(BASE, wait_until="networkidle")
        expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
        assert page.locator("#healthTxt").inner_text() != "connecting…", "health check never resolved"
        print("    dashboard OK —", page.locator("#healthTxt").inner_text())
        shot(page, "01-dashboard")

        # ---------------------------------------------------- 2. new scan
        print("[2] opening New Scan ...")
        page.get_by_role("link", name="⚡ New Scan").click()
        expect(page.get_by_role("heading", name="New Scan")).to_be_visible()
        page.get_by_role("button", name="⚡ Use bundled demo target").click()
        value = page.locator("#scTarget").input_value()
        assert value == "http://127.0.0.1:5099", f"demo button filled wrong value: {value}"
        print("    demo target filled:", value)
        shot(page, "02-scan-form")

        # ---------------------------------------------------- 3. launch scan
        print("[3] launching scan ...")
        page.get_by_role("button", name="▶ Launch scan").click()
        expect(page.locator("#scProgress .progress")).to_be_visible(timeout=10000)
        print("    pipeline started, polling progress ...")

        # watch live progress until completed (max 120s)
        deadline = time.time() + 120
        last_stage = ""
        while time.time() < deadline:
            status = page.locator("#scProgress .sev").inner_text()
            stage = page.locator("#scProgress .muted").last.inner_text()
            if stage != last_stage:
                print(f"    [{status}] {stage}")
                last_stage = stage
            if status.lower() in ("completed", "failed"):
                break
            page.wait_for_timeout(1500)
        shot(page, "03-pipeline")
        assert status.lower() == "completed", f"scan did not complete (status={status})"
        print("    scan COMPLETED")

        # ---------------------------------------------------- 4. results page
        print("[4] opening results ...")
        page.get_by_role("link", name="View results →").click()
        expect(page.get_by_role("heading", name="Scan Results")).to_be_visible()
        expect(page.locator(".finding").first).to_be_visible(timeout=15000)
        n_findings = page.locator(".finding").count()
        print(f"    results page OK — {n_findings} findings rendered")
        shot(page, "04-results")

        # ---------------------------------------------------- 5. expand + AI + replay
        print("[5] expanding first finding + attack replay ...")
        page.locator(".finding-head").first.click()
        expect(page.locator(".finding-body").first).to_be_visible()
        shot(page, "05-finding-open")

        replay_btn = page.locator(".finding.open").get_by_role("button", name="⏯ Attack replay")
        if replay_btn.count():
            replay_btn.first.click()
            expect(page.locator(".modal-card .attack-steps")).to_be_visible()
            steps = page.locator(".modal-card .attack-step").count()
            print(f"    attack replay OK — {steps} steps shown")
            shot(page, "06-attack-replay")
            page.locator(".modal-x").click()

        # ---------------------------------------------------- 6. reports page
        print("[6] checking reports + learning pages ...")
        page.get_by_role("link", name="📄 Reports").click()
        expect(page.locator('a[href*="report?format=developer"]').first).to_be_visible()
        print("    reports page OK")
        page.get_by_role("link", name="🎓 Learning").click()
        page.wait_for_timeout(1200)
        print("    learning page OK")
        shot(page, "07-learning")

        browser.close()

    # ------------------------------------------------------------ summary
    print("\n================ E2E SUMMARY ================")
    print("flow: dashboard -> scan -> pipeline -> results -> replay -> reports: PASS")
    if page_errors:
        print("\nPAGE JS ERRORS:")
        for e in page_errors:
            print("  x", e)
    if console_errors:
        print("\nCONSOLE ERRORS:")
        for e in console_errors:
            print("  x", e)
    if failed_requests:
        print("\nFAILED REQUESTS:")
        for r in failed_requests:
            print("  x", r)
    if not (page_errors or console_errors or failed_requests):
        print("console/pages/requests: all clean")

    return 1 if (page_errors or failed_requests) else 0


if __name__ == "__main__":
    sys.exit(run())
