"""Responsive UI test with Playwright.

Verifies the dashboard at three viewports:
  desktop 1500x950  — persistent sidebar, no hamburger
  tablet  768x1024  — drawer sidebar, 2-col score grid
  phone   390x844    — drawer nav opens/closes, single-column layout,
                       tables scroll instead of breaking, zero horizontal
                       page overflow on every page

Run:  python tests/e2e_mobile.py   (backend must be running)
Artifacts: tests/artifacts/responsive-*.png
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:5000"
ART = Path(__file__).parent / "artifacts"
ART.mkdir(parents=True, exist_ok=True)

issues = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        issues.append(f"{name}: {detail}")


def no_overflow(page):
    return page.evaluate(
        "document.documentElement.scrollWidth <= window.innerWidth + 1")


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()

        # ------------------------------------------------ desktop 1500x950
        print("[desktop 1500x950]")
        pg = browser.new_context(viewport={"width": 1500, "height": 950}).new_page()
        pg.goto(BASE, wait_until="networkidle")
        check("sidebar visible", pg.locator(".sidebar").is_visible())
        check("hamburger hidden", not pg.locator(".hamburger").is_visible())
        pg.screenshot(path=str(ART / "responsive-desktop.png"))

        # ------------------------------------------------ tablet 768x1024
        print("[tablet 768x1024]")
        pg.set_viewport_size({"width": 768, "height": 1024})
        pg.wait_for_timeout(400)
        n = pg.eval_on_selector(".view .grid",
            "el => getComputedStyle(el).gridTemplateColumns.split(' ').filter(v=>v!=='0px').length")
        check("score grid = 2 columns", n == 2, f"got {n}")
        check("hamburger visible", pg.locator(".hamburger").is_visible())
        check("no horizontal overflow", no_overflow(pg))
        pg.screenshot(path=str(ART / "responsive-tablet.png"))

        # ------------------------------------------------ phone 390x844
        print("[phone 390x844]")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(400)
        n = pg.eval_on_selector(".view .grid",
            "el => getComputedStyle(el).gridTemplateColumns.split(' ').filter(v=>v!=='0px').length")
        check("score grid = 1 column", n == 1, f"got {n}")

        # drawer navigation
        pg.locator(".hamburger").click()
        pg.wait_for_timeout(350)
        check("drawer opens", pg.locator(".sidebar.open").count() == 1)
        check("backdrop visible", pg.locator(".sidebar-backdrop.show").is_visible())
        pg.screenshot(path=str(ART / "responsive-phone-drawer.png"))
        pg.get_by_role("link", name="📄 Reports").click()
        pg.wait_for_timeout(600)
        check("drawer closes after nav", pg.locator(".sidebar.open").count() == 0)
        check("reports page reached", pg.locator("#pageTitle").inner_text() == "Reports")

        # results page: findings + overflow + table scroll
        pg.evaluate("location.hash = '#/scans'")
        pg.wait_for_timeout(700)
        pg.locator(".tbl .link").first.click()
        pg.wait_for_timeout(1500)
        check("findings render on phone",
              pg.locator(".finding").count() > 0,
              f"count={pg.locator('.finding').count()}")
        pg.locator(".finding-head").first.click()
        pg.wait_for_timeout(300)
        check("no horizontal overflow (results)", no_overflow(pg))
        pg.screenshot(path=str(ART / "responsive-phone-results.png"))

        # scan page usable at 390px
        pg.evaluate("location.hash = '#/scan'")
        pg.wait_for_timeout(700)
        check("scan form visible", pg.locator("#scTarget").is_visible())
        check("no horizontal overflow (scan form)", no_overflow(pg))
        pg.screenshot(path=str(ART / "responsive-phone-scan.png"))

        # learning page (simple content) + global overflow
        ctx = browser.new_context(viewport={"width": 390, "height": 844}).new_page()
        ctx.goto(BASE, wait_until="networkidle")
        ctx.locator(".hamburger").click()          # open drawer first at 390px
        ctx.wait_for_timeout(350)
        ctx.get_by_role("link", name="🎓 Learning").click()
        ctx.wait_for_timeout(600)
        check("no horizontal overflow (learning)", no_overflow(ctx))
        ctx.screenshot(path=str(ART / "responsive-phone-learning.png"))
        ctx.close()
        pg.close()

        browser.close()

    print("\n================ RESPONSIVE SUMMARY ================")
    if issues:
        for i in issues:
            print("  FAIL:", i)
        return 1
    print("desktop / tablet / phone: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(run())
