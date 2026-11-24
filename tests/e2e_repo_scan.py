"""E2E test for the universal repo-scanning mode (Playwright).

Drives the dashboard UI: New Scan -> Local Folder tab -> fixture project
-> launch -> poll -> results page with static findings, code-trace modal.

Run:  python tests/e2e_repo_scan.py   (backend must be running)
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:5000"
FIXTURE = str(Path(__file__).parent / "fixture_repo")
ART = Path(__file__).parent / "artifacts"
ART.mkdir(parents=True, exist_ok=True)

fails = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_context(viewport={"width": 1500, "height": 950}).new_page()
        pg.goto(BASE, wait_until="networkidle")

        # ------------------------------------------------ scan type tabs
        print("[repo mode e2e]")
        pg.get_by_role("link", name="New Scan").click()
        pg.get_by_role("button", name="GitHub Repo").click()
        check("github tab shows URL field", pg.locator("#scRepoUrl").is_visible())
        pg.get_by_role("button", name="Local Folder").click()
        check("local tab shows path field", pg.locator("#scLocalPath").is_visible())
        pg.get_by_role("button", name="API Target").click()
        check("api tab restores target field", pg.locator("#scTarget").is_visible())
        pg.get_by_role("button", name="Local Folder").click()

        # ------------------------------------------------ launch scan
        print(f"    scanning fixture: {FIXTURE}")
        pg.locator("#scLocalPath").fill(FIXTURE)
        pg.get_by_role("button", name="Launch scan").click()
        pg.wait_for_timeout(1500)
        expect_running = pg.locator("#scProgress .sev").count() > 0
        check("pipeline started", expect_running)

        import time
        # static analysis + AI verification agents (one LLM batch per group)
        # run against the real model — free-tier inference is ~45-90s per call.
        deadline, status = time.time() + 600, ""
        while time.time() < deadline:
            status = pg.locator("#scProgress .sev").inner_text().lower()
            if status in ("completed", "failed"):
                break
            pg.wait_for_timeout(1500)
        check("scan completed", status == "completed", f"status={status}")
        stage = pg.locator("#scProgress .muted").last.inner_text()
        print("    final stage:", stage)
        if status != "completed":
            pg.screenshot(path=str(ART / "repo-fail.png"))
            browser.close()
            print("FAILED:", fails)
            return 1

        # ------------------------------------------------ results page
        pg.get_by_role("link", name="View results →").click()
        pg.wait_for_timeout(2000)
        n = pg.locator(".finding").count()
        check("static findings rendered", n >= 10, f"count={n}")
        static_badges = pg.locator(".finding-head .sev", has_text="static").count()
        check("STATIC badges shown", static_badges >= 5, f"got {static_badges}")
        check("repo chips (files/LOC)", "files" in pg.locator(".scanbar").inner_text())

        has_sqli = "SQL" in pg.locator(".finding .title").first.inner_text() \
            or any("SQL" in pg.locator(".finding .title").nth(i).inner_text()
                   for i in range(min(n, 6)))
        check("SQLi (static) present in list", has_sqli)
        pg.screenshot(path=str(ART / "repo-results.png"))

        # ------------------------------------------------ code trace modal
        pg.locator(".finding-head").first.click()
        pg.wait_for_timeout(300)
        btn = pg.locator(".finding.open").get_by_role("button", name="Code trace")
        if btn.count():
            btn.first.click()
            steps = pg.locator(".modal-card .attack-step").count()
            check("code trace modal opens", steps >= 3, f"steps={steps}")
            pg.screenshot(path=str(ART / "repo-code-trace.png"))
            pg.locator(".modal-x").click()

        # ------------------------------------------------ dashboard switcher
        pg.get_by_role("link", name="Dashboard").click()
        pg.wait_for_timeout(1500)
        sel = pg.locator("#dashScanSel")
        check("dashboard scan switcher visible", sel.count() == 1)
        if sel.count():
            opts = sel.locator("option").count()
            check("switcher has multiple scans", opts >= 2, f"opts={opts}")

        browser.close()

    print("\n================ REPO MODE E2E =================")
    if fails:
        for f in fails:
            print("  FAIL:", f)
        return 1
    print("repo scanning: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(run())
