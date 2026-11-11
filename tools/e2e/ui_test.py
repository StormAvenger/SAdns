#!/usr/bin/env python3
# End-to-end UI test: logs in, renders every view at mobile/tablet/laptop/desktop
# widths in light and dark mode (screenshots), checks switch geometry, focus,
# reduced motion/transparency, history compare/pin, trends, CSP errors, and
# runs a real scan from the dashboard.
# Usage: python3 tools/e2e/ui_test.py <sadns-binary> <data-dir-with-history> <screenshot-dir>
# Needs: pip install playwright (uses an installed Chrome; set CHROME=path).
import json, os, subprocess, sys, time
from playwright.sync_api import sync_playwright

BIN, DATA, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(OUT, exist_ok=True)
PW = "e2e test password 123"
env = dict(os.environ, SADNS_PASSWORD=PW, SADNS_LISTEN="127.0.0.1:18099", SADNS_DATA_DIR=DATA)
srv = subprocess.Popen([BIN, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1.5)
URL = "http://127.0.0.1:18099/"
fails, errors = [], []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

WIDTHS = {"mobile": 390, "tablet": 820, "laptop": 1280, "desktop": 1680}
try:
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("CHROME", "/usr/bin/google-chrome"), args=["--no-sandbox"])
        ctx = b.new_context(viewport={"width": 1280, "height": 900}, color_scheme="dark")
        pg = ctx.new_page()
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(URL)
        pg.wait_for_selector("#pw")
        pg.screenshot(path=f"{OUT}/login.png")
        pg.fill("#pw", "wrong password!!")
        pg.click("button[type=submit]")
        pg.wait_for_selector('#lerr:not(:empty)')
        check("not correct" in pg.inner_text("#lerr"), "wrong password shows an error")
        pg.fill("#pw", PW); pg.click("button[type=submit]")
        pg.wait_for_selector(".hero")
        check(pg.locator(".node").count() == 6, "path rail has six layers")

        for theme in ["dark", "light"]:
            pg.evaluate(f"localStorage.setItem('sadns-theme','{theme}')")
            for name, w in WIDTHS.items():
                pg.set_viewport_size({"width": w, "height": 900 if w > 500 else 844})
                for view in ["dashboard", "results", "history", "trends", "settings"]:
                    pg.goto(URL + "#/" + view); pg.reload(); pg.wait_for_selector("main header, main .hero, main .stack", timeout=8000)
                    pg.wait_for_timeout(250)
                    # No horizontal page overflow at any width.
                    ow = pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    check(ow <= 1, f"{theme}/{name}/{view}: no horizontal overflow ({ow}px)")
                    pg.screenshot(path=f"{OUT}/{view}-{name}-{theme}.png", full_page=(view != "results"))
                    if view == "settings":
                        boxes = pg.evaluate("""[...document.querySelectorAll('.sw')].filter(e=>e.offsetParent).map(e=>{const r=e.getBoundingClientRect();const g=e.closest('.group').getBoundingClientRect();return [r.width,r.height,Math.round(g.right-r.right)]})""")
                        sizes = {(round(a), round(bb)) for a, bb, _ in boxes}
                        rights = {c for _, _, c in boxes}
                        check(len(boxes) >= 9 and sizes == {(46, 28)}, f"{theme}/{name}: all {len(boxes)} switches are 46x28 ({sizes})")
                        check(max(rights) - min(rights) <= 1, f"{theme}/{name}: switches share one right-hand column ({rights})")
        pg.evaluate("localStorage.setItem('sadns-theme','dark')")
        pg.set_viewport_size({"width": 1280, "height": 900})

        # Whole row toggles; keyboard focus visible.
        pg.goto(URL + "#/settings"); pg.reload(); pg.wait_for_selector("#p-tr")
        before = pg.is_checked("#p-tr")
        pg.click("label[for=p-tr] .lab b")
        pg.wait_for_timeout(600)
        check(pg.is_checked("#p-tr") != before, "clicking the row label toggles the switch")
        pg.click("label[for=p-tr] .lab b"); pg.wait_for_timeout(600)
        pg.focus("#p-enc"); pg.keyboard.press("Space"); pg.wait_for_timeout(600)
        pg.focus("#p-enc")
        oc = pg.evaluate("getComputedStyle(document.querySelector('label[for=p-enc]')).outlineStyle")
        check(oc != "none", "focused settings row shows a focus outline")
        pg.keyboard.press("Space"); pg.wait_for_timeout(600)
        pg.keyboard.press("Tab")
        check(pg.evaluate("document.activeElement !== document.body"), "Tab moves focus")

        # Auto Run: invalid then valid.
        pg.fill("input[aria-label=Interval]", "2"); pg.select_option("select[aria-label='Interval unit']", "minutes")
        pg.click("text=Save Auto Run"); pg.wait_for_timeout(500)
        check("at least" in pg.inner_text("#toast").lower() or "between" in pg.inner_text("#toast").lower(), "2-minute interval rejected with a message")
        pg.click("label[for=a-en] .lab b")
        pg.fill("input[aria-label=Interval]", "6"); pg.select_option("select[aria-label='Interval unit']", "hours")
        pg.click("text=Save Auto Run"); pg.wait_for_timeout(700)
        check(pg.locator("text=Next run:").count() == 1 and "in " in pg.inner_text("main"), "Auto Run enabled shows next run")
        pg.click("button:has-text('Pause')"); pg.wait_for_timeout(500)
        check(pg.locator("button:has-text('Resume')").count() == 1, "pause switches to Resume")
        pg.click("button:has-text('Resume')"); pg.wait_for_timeout(500)
        pg.screenshot(path=f"{OUT}/settings-autorun.png", full_page=True)

        # Reduced motion & transparency.
        rm = b.new_context(viewport={"width": 1280, "height": 900}, reduced_motion="reduce")
        rp = rm.new_page(); rp.goto(URL); rp.fill("#pw", PW); rp.click("button[type=submit]"); rp.wait_for_selector(".hero")
        td = rp.evaluate("getComputedStyle(document.querySelector('.btn')).transitionDuration")
        check(td in ("0s", "0s, 0s"), f"reduced motion disables transitions ({td})")
        rp.evaluate("localStorage.setItem('sadns-transparency','reduced')"); rp.reload(); rp.wait_for_selector(".hero")
        bf = rp.evaluate("getComputedStyle(document.querySelector('.glass')).backdropFilter")
        check(bf == "none", f"reduced transparency removes the blur ({bf})")
        rp.screenshot(path=f"{OUT}/dashboard-reduced-transparency.png")
        rm.close()

        # History: compare two, view one, pin.
        pg.goto(URL + "#/history"); pg.reload(); pg.wait_for_selector(".hrow")
        n = pg.locator(".hrow").count()
        check(n >= 3, f"history lists {n} stored scans after restart")
        cbs = pg.locator(".hrow input[type=checkbox]")
        cbs.nth(0).check(); pg.wait_for_timeout(200); pg.locator(".hrow input[type=checkbox]").nth(1).check(); pg.wait_for_timeout(200)
        pg.click("text=Compare selected"); pg.wait_for_selector("text=Comparison")
        pg.screenshot(path=f"{OUT}/history-compare.png", full_page=True)
        pg.locator(".hrow .pin").first.click(); pg.wait_for_timeout(500)
        check(pg.locator(".hrow .pin[aria-pressed=true]").count() >= 1, "pin toggles")
        pg.locator(".hrow button:has-text('View')").nth(1).click(); pg.wait_for_selector(".tabs")
        for t in ["Resolvers", "Network", "Connectivity", "System", "Routing", "AI report", "Findings"]:
            pg.click(f".tabs button:has-text('{t}')"); pg.wait_for_timeout(300)
        check("AI" in pg.content(), "every results tab renders")
        pg.goto(URL + "#/trends"); pg.wait_for_selector("svg.chart")
        check(pg.locator("svg.chart").count() >= 3, "trend charts render")

        # Run a real scan from the dashboard and watch it finish.
        pg.goto(URL + "#/dashboard"); pg.wait_for_selector(".hero")
        pg.click("button:has-text('Run diagnostics')")
        pg.wait_for_selector("#pbar", timeout=5000)
        pg.wait_for_timeout(2500)
        pg.screenshot(path=f"{OUT}/dashboard-running.png")
        pg.wait_for_selector("button:has-text('Run diagnostics')", timeout=180000)
        pg.wait_for_timeout(800)
        pg.screenshot(path=f"{OUT}/dashboard-after-scan.png", full_page=True)
        check(pg.locator(".hrow").count() == 0, "back on dashboard after scan")
        b.close()
finally:
    srv.terminate(); srv.wait()
csp = [e for e in errors if "Content Security Policy" in e or "Refused" in e]
check(not csp, f"no CSP violations ({csp[:2]})")
check(not [e for e in errors if "Refused" not in e and "status of 401" not in e and "status of 400" not in e], f"no script errors ({errors[:3]})")
print("\n%d failures" % len(fails)); sys.exit(1 if fails else 0)
