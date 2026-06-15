"""
====================================
  Dataset Builder  —  v2 (Diverse)
====================================
Creates a CSV dataset with realistic & diverse URLs
  0 = Legitimate
  1 = Phishing

Key improvements over v1:
  - Legit URLs include /login, /account, hyphens → no more HTTP=phishing shortcut
  - Phishing URLs include HTTPS, lookalike domains, subdomain abuse
  - Mix of TLDs in both classes
  - Varied URL lengths on both sides
"""

import csv
import os
import time

LEGITIMATE_URLS = [
    # ── Major platforms ──────────────────────────────────────────
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.netflix.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.bbc.com/news",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.ebay.com",
    "https://www.paypal.com",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://www.twitch.tv",
    "https://www.airbnb.com",
    "https://www.booking.com",
    "https://www.tripadvisor.com",
    "https://www.imdb.com",

    # ── Real login pages (legit with /login or /signin) ──────────
    # These used to fool models trained on v1 data
    "https://accounts.google.com/signin",
    "https://accounts.google.com/v3/signin/identifier",
    "https://login.microsoftonline.com",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://www.facebook.com/login",
    "https://www.facebook.com/login/device-based/regular/login",
    "https://github.com/login",
    "https://github.com/login?return_to=%2Fexplore",
    "https://www.linkedin.com/login",
    "https://www.linkedin.com/uas/login",
    "https://login.yahoo.com",
    "https://appleid.apple.com/sign-in",
    "https://www.instagram.com/accounts/login",
    "https://www.twitter.com/i/flow/login",
    "https://www.reddit.com/login",
    "https://www.twitch.tv/login",
    "https://www.dropbox.com/login",
    "https://www.spotify.com/eg/login",
    "https://www.ebay.com/signin",
    "https://signin.ebay.com/ws/eBayISAPI.dll",
    "https://www.amazon.com/ap/signin",
    "https://secure.netflix.com/login",
    "https://www.paypal.com/signin",

    # ── Real account/verify/update pages (legit) ─────────────────
    "https://www.amazon.com/account/homepage",
    "https://account.microsoft.com",
    "https://myaccount.google.com",
    "https://myaccount.google.com/security",
    "https://www.paypal.com/myaccount/summary",
    "https://www.netflix.com/youraccount",
    "https://www.netflix.com/account/update-primary-email",
    "https://account.live.com/password/reset",
    "https://www.amazon.com/gp/css/account/info",
    "https://www.apple.com/account",
    "https://support.apple.com/account",
    "https://www.linkedin.com/psettings/account",
    "https://www.instagram.com/accounts/manage_access",
    "https://security.google.com/settings/security/secureaccount",
    "https://www.facebook.com/settings?tab=account",
    "https://www.github.com/settings/billing/update",

    # ── Legit sites with hyphens in domain (common mistake) ───────
    "https://www.coca-cola.com",
    "https://www.t-mobile.com",
    "https://www.t-mobile.com/home",
    "https://aws-portal.amazon.com",
    "https://www.well-beingindex.com",
    "https://www.stack-overflow.com",
    "https://login.live.com",
    "https://login.live.com/login.srf",
    "https://self-service.adobe.com",
    "https://developer-tools.google.com",
    "https://open-platform.twitter.com",
    "https://my-account.autodesk.com",
    "https://app-directory.slack.com",
    "https://help-center.medium.com",

    # ── Tech & Dev ────────────────────────────────────────────────
    "https://www.python.org",
    "https://reactjs.org",
    "https://vuejs.org",
    "https://angular.io",
    "https://nodejs.org",
    "https://www.djangoproject.com",
    "https://flask.palletsprojects.com",
    "https://fastapi.tiangolo.com",
    "https://www.postgresql.org",
    "https://www.mongodb.com",
    "https://redis.io",
    "https://www.docker.com",
    "https://kubernetes.io",
    "https://aws.amazon.com",
    "https://azure.microsoft.com",
    "https://cloud.google.com",
    "https://vercel.com",
    "https://netlify.com",
    "https://www.digitalocean.com",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://www.jetbrains.com",
    "https://code.visualstudio.com",
    "https://www.postman.com",
    "https://swagger.io",
    "https://www.nginx.com",
    "https://docs.python.org",
    "https://www.w3schools.com",

    # ── News & Media ──────────────────────────────────────────────
    "https://www.theguardian.com",
    "https://www.washingtonpost.com",
    "https://www.forbes.com",
    "https://www.bloomberg.com",
    "https://www.reuters.com",
    "https://www.apnews.com",
    "https://www.aljazeera.com",
    "https://www.npr.org",
    "https://www.wired.com",
    "https://www.techcrunch.com",
    "https://www.theverge.com",
    "https://arstechnica.com",
    "https://www.cnet.com",
    "https://www.zdnet.com",

    # ── Finance & Shopping ────────────────────────────────────────
    "https://www.visa.com",
    "https://www.mastercard.com",
    "https://www.chase.com",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://www.schwab.com",
    "https://www.fidelity.com",
    "https://www.coinbase.com",
    "https://www.stripe.com",
    "https://www.walmart.com",
    "https://www.target.com",
    "https://www.bestbuy.com",
    "https://www.etsy.com",
    "https://www.aliexpress.com",
    "https://www.ikea.com",

    # ── Education ─────────────────────────────────────────────────
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.khanacademy.org",
    "https://www.edx.org",
    "https://www.duolingo.com",
    "https://www.codecademy.com",
    "https://www.freecodecamp.org",
    "https://www.harvard.edu",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.ox.ac.uk",

    # ── Health & Gov ──────────────────────────────────────────────
    "https://www.who.int",
    "https://www.cdc.gov",
    "https://www.nih.gov",
    "https://www.mayoclinic.org",
    "https://www.webmd.com",
    "https://www.usa.gov",
    "https://www.gov.uk",
    "https://www.nasa.gov",
    "https://www.whitehouse.gov",

    # ── Productivity & Tools ──────────────────────────────────────
    "https://asana.com",
    "https://monday.com",
    "https://www.notion.so",
    "https://www.trello.com",
    "https://www.canva.com",
    "https://www.figma.com",
    "https://www.grammarly.com",
    "https://www.deepl.com",
    "https://translate.google.com",
    "https://www.wolframalpha.com",
    "https://www.archive.org",
    "https://www.zoom.us",
    "https://www.slack.com",
    "https://discord.com",
    "https://telegram.org",
    "https://meet.google.com",
    "https://teams.microsoft.com",

    # ── Social ────────────────────────────────────────────────────
    "https://www.whatsapp.com",
    "https://www.tiktok.com",
    "https://www.tumblr.com",
    "https://www.flickr.com",
    "https://www.pinterest.com",
    "https://www.snapchat.com",
    "https://www.deviantart.com",
    "https://www.quora.com",
    "https://www.medium.com",

    # ── Realistic subpages with query strings ─────────────────────
    "https://www.amazon.com/dp/B08N5KWB9H",
    "https://www.amazon.com/s?k=laptop&ref=nav",
    "https://github.com/torvalds/linux",
    "https://github.com/settings/profile",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://docs.python.org/3/library/urllib.html",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.reddit.com/r/programming",
    "https://www.linkedin.com/in/username",
    "https://www.netflix.com/browse",
    "https://drive.google.com/drive/my-drive",
    "https://calendar.google.com/calendar/r",
    "https://maps.google.com",
    "https://news.google.com",
    "https://play.google.com/store",
    "https://photos.google.com",
    "https://www.adobe.com",
    "https://www.oracle.com",
    "https://www.ibm.com",
    "https://www.salesforce.com",
    "https://www.shopify.com",
    "https://www.wordpress.com",
]


PHISHING_URLS = [
    # ── HTTPS phishing (tricky — model can't rely on http alone) ──
    "https://paypa1.com/login/secure/verify",
    "https://arnazon-orders.com/account/verify",
    "https://g00gle-security.com/alert/action",
    "https://faceb00k-login.net/confirm/identity",
    "https://rnicrosoft.net/security/update",
    # Pure lookalike domains (no obvious path keywords)
    "https://www.g00gle.com",
    "https://www.rnicrosoft.com",
    "https://www.go0gle.com",
    "https://www.goog1e.com",
    "https://www.micr0soft.com",
    "https://www.rn1crosoft.com",
    "https://www.faceb00k.com",
    "https://www.instagrarn.com",
    "https://www.amaz0n.com",
    "https://www.arnazon.com",
    "https://www.paypa1.com",
    "https://www.app1e.com",
    "https://www.netf1ix.com",
    "https://www.tw1tter.com",
    "https://www.linkedln.com",
    "https://www.dropb0x.com",
    "https://app1e-id-verify.com/signin",
    "https://paypal-secure.harvested.net/login",
    "https://secure-amazon.phishcdn.com/verify",
    "https://google-accounts.auth-now.com/signin",
    "https://microsoft-login.malicioussite.net/auth",
    "https://apple-support.fake-login.com/id/verify",
    "https://netflix-secure.credential-harvest.com",
    "https://icloud-unlock.phish-now.com/verify",
    "https://linkedin-auth.stolen-creds.net/login",
    "https://instagram-verify.badactor.com/confirm",

    # ── Subdomain abuse (brand.evil.com) ─────────────────────────
    "http://paypal.verify-account-now.com/update",
    "http://amazon.order-support-help.com/claim",
    "http://google.account-security-alert.com/verify",
    "http://apple.id-restore-help.com/fix",
    "http://microsoft.account-suspended-now.com/login",
    "http://facebook.login-confirm-identity.com",
    "http://netflix.billing-update-required.com/pay",
    "http://ebay.account-verify-login.com/signin",
    "http://dropbox.file-shared-urgent.com/open",
    "http://twitter.account-restore-help.com/fix",
    "https://paypal.phish-secure.com/wallet/signin",
    "https://amazon.prize-winner-confirm.net/claim",
    "https://apple.icloud-restore.malicious.com/verify",

    # ── Lookalike / typosquat domains ─────────────────────────────
    "http://paypa1.com/account/login",
    "http://paypai.com/secure/signin",
    "http://arnazon.com/account/verify",
    "http://amazom.com/orders/update",
    "http://goggle.com/accounts/login",
    "http://gooogle.com/security/verify",
    "http://faceb00k.com/login/confirm",
    "http://facebok.com/account/verify",
    "http://rnicrosoftcom/security/alert",
    "http://micosoft.com/account/login",
    "http://app1e.com/id/verify",
    "http://aple.com/support/signin",
    "http://netfl1x.com/account/payment",
    "http://linkedln.com/login/verify",
    "http://twiiter.com/account/suspended",
    "https://paypa1.net/wallet/update",
    "https://arnazon.net/prime/renew",
    "https://g00gle.net/account/security",

    # ── IP-based ──────────────────────────────────────────────────
    "http://192.168.1.1/login.php",
    "http://193.42.61.10/paypal/login",
    "http://10.0.0.1/admin/login.php",
    "http://172.16.0.1/account/verify",
    "http://185.220.101.45/banking/login",
    "http://91.108.4.1/secure/account",
    "http://45.33.32.156/update/password",
    "http://198.51.100.1/login/confirm",
    "http://203.0.113.1/verify/identity",
    "http://176.9.0.1/account/suspended",

    # ── Classic PayPal phishing ───────────────────────────────────
    "http://paypal-secure-login.verify-account.com/update",
    "http://paypal-account-locked.click/unlock",
    "http://paypal-money-waiting.click-collect.com",
    "http://confirm-your-paypal.fishy-domain.net/login",
    "http://paypal-verify-account.login-now.tk/secure",
    "http://paypal-suspended.account-restore.ml/verify",
    "http://paypal-billing-update.click-here.info/pay",

    # ── Amazon phishing ───────────────────────────────────────────
    "http://amazon-account-suspended.com/verify?id=12345",
    "http://amazon-winner-free-gift.com/claim",
    "http://account-suspended-amazon-verify.ml/restore",
    "http://winner-notification-amazon-gift.com/claim",
    "http://amazon-prime-account.verify-now.tk/login",
    "http://amazon-billing-error.update-now.net/payment",

    # ── Google phishing ───────────────────────────────────────────
    "http://google-account-verify.login-secure.tk",
    "http://emergency-account-alert-google.com/verify",
    "http://gmail-account-hacked.recover-now.tk",
    "http://google-docs-shared-file.malware.net/open",
    "http://google-account-suspended.restore-now.ml/fix",
    "http://gmail-password-reset.urgent-now.tk/recover",

    # ── Facebook phishing ─────────────────────────────────────────
    "http://facebook-login-confirm.com/account/update",
    "http://account-locked-facebook.com/restore",
    "http://facebook-security-alert.phish-link.com/verify",
    "http://facebook-free-followers.click-get.com/boost",
    "http://facebook-prize-winner.claim-now.xyz/get",

    # ── Apple phishing ────────────────────────────────────────────
    "http://apple-id-verify.suspicious-site.ml",
    "http://apple-support-virus-alert.com/fix",
    "http://apple-id-suspended.restore-account.tk/fix",
    "http://icloud-account-locked.restore-now.ml/login",
    "http://apple-payment-failed.update-billing.com/pay",

    # ── Microsoft phishing ────────────────────────────────────────
    "http://microsoft-support-alert.com/fix/virus",
    "http://microsoft-antivirus-alert.scam-site.com",
    "http://urgent-security-alert.fake-microsoft.com",
    "http://microsoft-account-suspended.restore.tk/login",
    "http://office365-login-verify.phish-link.net/signin",

    # ── Banking phishing ──────────────────────────────────────────
    "http://secure-banking-login@phish.xyz/verify",
    "http://bankofamerica-secure.phishing-domain.com",
    "http://bank-secure-login.phish-site.ru/verify",
    "http://your-visa-card-blocked.bank-phish.ru",
    "http://chase-bank-alert.verify-login.net/signin",
    "http://wellsfargo-secure.account-verify.com/login",
    "http://citibank-account-locked.restore.xyz/fix",
    "http://hsbc-secure-login.phish-domain.com/verify",
    "https://secure-chase-bank.credential-steal.com/login",
    "https://wellsfargo-online.phish-secure.net/verify",

    # ── Netflix / eBay / Twitter phishing ─────────────────────────
    "http://netflix-billing-update.com/account/payment",
    "http://netflix-account-suspended.restore.tk/login",
    "http://netflix-free-month.click-claim.com/get",
    "http://ebay-suspended-account.login-verify.net",
    "http://ebay-free-gift.winner-claim.xyz/collect",
    "http://twitter-login.verify-account-secure.com",
    "http://twitter-account-suspended.restore.tk/fix",
    "http://instagram-account-locked.verify-now.com/login",

    # ── Dropbox phishing ──────────────────────────────────────────
    "http://dropbox-file-shared.malicious-link.org/open",
    "http://dropbox-important-file.phish-domain.com/view",
    "http://shared-file-dropbox.malware-link.com/open",

    # ── Long obfuscated URLs ──────────────────────────────────────
    "http://secure-update.com/account/login/verify/identity/confirm?token=a1b2c3&redirect=paypal.com",
    "http://login-verification.com/user/account/secure/signin/confirm?session=xyz&ref=amazon",
    "http://account-restore.net/verify/identity/step1/step2/confirm?id=99&src=google.com",
    "https://phish-secure.com/paypal/login/verify?email=victim@mail.com&token=abc123secure",
    "https://data-collect.net/amazon/signin?redirect=amazon.com&session=steal123",

    # ── Generic / prize / virus scams ────────────────────────────
    "http://win-free-iphone.click-here-now.com",
    "http://verify-your-account-immediately.com/secure",
    "http://free-gift-amazon-winner.com/claim/now",
    "http://your-account-has-been-compromised.info",
    "http://free-robux-generator.click-hack.com",
    "http://click-here-to-unlock-account.phish.ml",
    "http://account-suspended-restore.click-now.com/fix",
    "http://free-prize-winner-claim.click-get.com/now",
    "http://win-big-prize.claim-reward.click/get-now",
    "http://virus-detected-fix-now.microsoft-alert.com",
    "http://your-computer-infected.click-clean.net/fix",
    "https://free-netflix-subscription.win-now.com/claim",
    "https://congratulations-winner.prize-collect.net/get",
]


def _write_dataset_file(output_path: str, include_features: bool = True) -> None:
    # Import locally to avoid import side-effects when this module is imported elsewhere.
    # Also keeps dataset writing optional (URLs-only vs feature-rich CSV).
    if include_features:
        from feature_extractor import extract_features, get_feature_names
        feature_names = get_feature_names()
        header = ["url", "label"] + feature_names
    else:
        extract_features = None
        feature_names = []
        header = ["url", "label"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for url in LEGITIMATE_URLS:
            row = [url, 0]
            if include_features:
                feats = extract_features(url)
                row.extend([feats[n] for n in feature_names])
            writer.writerow(row)
        for url in PHISHING_URLS:
            row = [url, 1]
            if include_features:
                feats = extract_features(url)
                row.extend([feats[n] for n in feature_names])
            writer.writerow(row)


def create_dataset(output_path: str = "data/dataset.csv") -> str:
    """Write the dataset CSV. On Windows file locks, fall back to alternate paths."""
    dir_name = os.path.dirname(output_path) or "."
    os.makedirs(dir_name, exist_ok=True)

    base = os.path.basename(output_path)
    stem, ext = os.path.splitext(base)
    if not ext:
        ext = ".csv"

    candidates = [
        output_path,
        os.path.join(dir_name, f"{stem}_new{ext}"),
        os.path.join(dir_name, f"{stem}_{os.getpid()}_{int(time.time())}{ext}"),
    ]
    seen = set()
    ordered = []
    for p in candidates:
        if p not in seen:
            seen.add(p)
            ordered.append(p)

    last_err = None
    resolved_path = None
    for path in ordered:
        try:
            _write_dataset_file(path)
            resolved_path = path
            break
        except (PermissionError, OSError) as e:
            last_err = e
            print(f"  [dataset] Could not write {path!r}: {e}")
            continue

    if resolved_path is None:
        assert last_err is not None
        raise last_err

    if resolved_path != output_path:
        print(f"  [dataset] Using fallback path (primary file may be locked): {resolved_path!r}")

    total = len(LEGITIMATE_URLS) + len(PHISHING_URLS)
    print(f"Dataset v2 created successfully!")
    print(f"  Path       : {resolved_path}")
    print(f"  Legitimate : {len(LEGITIMATE_URLS)} URLs")
    print(f"  Phishing   : {len(PHISHING_URLS)} URLs")
    print(f"  Total      : {total} URLs")

    # Quick diversity check
    legit_http  = sum(1 for u in LEGITIMATE_URLS  if u.startswith("http://"))
    phish_https = sum(1 for u in PHISHING_URLS    if u.startswith("https://"))
    legit_login = sum(1 for u in LEGITIMATE_URLS  if "login" in u or "signin" in u)
    phish_https_pct = round(phish_https / len(PHISHING_URLS) * 100)
    print(f"\n  Diversity stats:")
    print(f"    Legit URLs with http://       : {legit_http}  (model can't use http=phishing)")
    print(f"    Phishing URLs with https://   : {phish_https} ({phish_https_pct}%)")
    print(f"    Legit URLs with /login|signin : {legit_login}")
    return resolved_path


if __name__ == "__main__":
    create_dataset()
