"""
====================================
  Phishing URL Feature Extractor — v2
====================================
Extracts features from a URL for the ML model

Fixes over v1:
  1. Keywords checked in DOMAIN only (not full URL) → legit /login pages stop firing
  2. has_hyphen_domain → num_hyphens_in_domain (count, not binary) + ratio
  3. num_subdomains now ignores 'www' correctly
  4. has_double_slash checks path correctly (was always wrong)
  5. has_ip_address uses stronger IPv4 regex (port-aware)
  6. NEW: has_suspicious_tld (.tk .ml .xyz .click .phish .ru .info)
  7. NEW: brand_in_domain (paypal/amazon/google in domain = typosquat signal)
  8. NEW: domain_has_digit (paypa1, g00gle, arnazon → digit in domain)
  9. NEW: keyword_in_domain vs keyword_in_path (separate signals)
 10. NEW: redirect_in_url (contains redirect= or return_to= → obfuscation)
"""

import re
import difflib
from urllib.parse import urlparse, parse_qs


# ── Helpers ────────────────────────────────────────────────────────────────

def _get_registered_domain(netloc: str) -> str:
    """Return just the registered domain (last 2 parts), excluding port."""
    host = netloc.split(":")[0]               # strip port
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _get_subdomains(netloc: str) -> list:
    """Return subdomain parts, ignoring www and port."""
    host = netloc.split(":")[0]
    parts = host.split(".")
    subs = parts[:-2]                          # remove registered domain
    return [s for s in subs if s.lower() != "www"]


def _domain_label(registered_domain: str) -> str:
    # "g00gle.com" -> "g00gle"
    return registered_domain.split(".")[0].lower()


def _deobfuscate_label(label: str) -> str:
    """
    Map common typosquat substitutions to their likely originals.
    Examples:
      g00gle -> google
      paypa1 -> paypal
      rnicrosoft -> microsoft (rn -> m)
    """
    s = label.lower()
    s = (
        s.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
        .replace("8", "b")
        .replace("9", "g")
        .replace("@", "a")
    )
    s = s.replace("rn", "m")
    return s


def _brand_similarity(label: str, brands: list) -> tuple:
    """
    Returns (max_ratio: float, matched_brand: str).
    Uses a few normalized variants to catch g00gle/rnicrosoft-style lookalikes.
    """
    base = re.sub(r"[^a-z0-9]", "", label.lower())
    variants = {base, _deobfuscate_label(base)}
    variants |= {v.replace("m", "rn") for v in list(variants)}

    best_ratio = 0.0
    best_brand = ""
    for brand in brands:
        b = re.sub(r"[^a-z0-9]", "", brand.lower())
        for v in variants:
            if not v:
                continue
            r = difflib.SequenceMatcher(None, v, b).ratio()
            if r > best_ratio:
                best_ratio = r
                best_brand = brand.lower()
    return best_ratio, best_brand


# ── Main extractor ─────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    features = {}

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed      = urlparse(url)
    netloc      = parsed.netloc                # includes port if present
    host        = netloc.split(":")[0]         # hostname only
    reg_domain  = _get_registered_domain(netloc)
    subdomains  = _get_subdomains(netloc)
    path        = parsed.path
    query       = parsed.query
    full_url    = url
    url_lower   = full_url.lower()
    host_lower  = host.lower()
    domain_lower = reg_domain.lower()

    # ── 1. URL Length ──────────────────────────────────────────
    features["url_length"]      = len(full_url)
    features["domain_length"]   = len(host)
    features["path_length"]     = len(path)
    features["is_long_url"]     = 1 if len(full_url) > 75 else 0

    # ── 2. Special Characters (full URL) ──────────────────────
    features["has_at_symbol"]       = 1 if "@" in full_url else 0
    features["num_dots"]            = full_url.count(".")
    features["num_hyphens"]         = full_url.count("-")
    features["num_underscores"]     = full_url.count("_")
    features["num_slashes"]         = full_url.count("/")
    features["num_question_marks"]  = full_url.count("?")
    features["num_equal_signs"]     = full_url.count("=")
    features["num_ampersands"]      = full_url.count("&")
    features["num_percent"]         = full_url.count("%")
    features["num_digits_in_url"]   = sum(c.isdigit() for c in full_url)

    # FIX 4 — double slash in PATH (after stripping leading /)
    features["has_double_slash"] = 1 if "//" in path.lstrip("/") else 0

    # ── 3. Domain Features ────────────────────────────────────

    # FIX 3 — subdomains: ignore 'www', count real subdomains only
    features["num_subdomains"] = len(subdomains)
    features["has_many_subdomains"] = 1 if len(subdomains) >= 3 else 0

    # FIX 5 — IP: port-aware regex
    _ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    features["has_ip_address"] = 1 if _ip_re.match(host) else 0

    # FIX 2 — hyphens in domain name only (not path)
    features["num_hyphens_in_domain"] = host.count("-")
    features["has_hyphen_domain"]     = 1 if "-" in host else 0

    # FIX 6 — suspicious TLD
    _suspicious_tlds = {
        "tk", "ml", "xyz", "click", "phish", "ru",
        "info", "gq", "cf", "ga", "pw", "top", "work"
    }
    tld = host.split(".")[-1].lower() if "." in host else ""
    features["has_suspicious_tld"] = 1 if tld in _suspicious_tlds else 0

    # FIX 7 — brand name appears in domain (typosquat / subdomain abuse)
    # e.g. paypal.evil.com  OR  paypa1.com  OR  paypal-secure.com
    _brands = [
        "paypal", "amazon", "google", "facebook", "apple",
        "microsoft", "netflix", "ebay", "instagram", "twitter",
        "dropbox", "linkedin", "chase", "wellsfargo", "bankofamerica",
        "chatgpt", "openai", "github", "binance", "x.com"
    ]
    label = _domain_label(domain_lower)
    # Only flag if brand is a substring but NOT the exact domain label
    # e.g., 'paypal.evil.com' or 'paypal-secure.com' triggers, but 'paypal.com' does not.
    features["brand_in_domain"] = int(any(b in host_lower and b != label for b in _brands))

    # NEW: brand match after deobfuscation (g00gle -> google, rnicrosoft -> microsoft, etc.)
    deob_label = _deobfuscate_label(re.sub(r"[^a-z0-9]", "", label))
    deob_host = _deobfuscate_label(re.sub(r"[^a-z0-9]", "", host_lower))
    features["brand_obfuscated_match"] = int(any(b in deob_host and b != deob_label for b in _brands))

    # NEW: lookalike / typosquat similarity (g00gle, rnicrosoft, etc.)
    _top_targets = [
        "google", "microsoft", "facebook", "amazon", "paypal", "apple", 
        "netflix", "chatgpt", "openai", "instagram", "linkedin", "github", 
        "binance", "twitter", "x"
    ]
    label = _domain_label(domain_lower)
    sim, matched = _brand_similarity(label, _top_targets)
    is_lookalike = int(sim >= 0.82 and label != matched)
    # Important: keep similarity "quiet" for exact brand domains so it doesn't
    # become a misleading legit-signal (e.g., google.com has sim=1.0).
    features["is_lookalike_domain"] = is_lookalike
    features["brand_similarity_score"] = float(sim) if is_lookalike else 0.0

    # FIX 8 — digit substitution in domain (paypa1, g00gle, m1crosoft)
    # Check registered domain part only
    features["domain_has_digit"] = 1 if any(c.isdigit() for c in domain_lower.split(".")[0]) else 0

    # ── 4. Keyword Features (FIXED) ───────────────────────────
    #
    # v1 BUG: checked keywords in FULL URL → legit /login pages scored high
    # v2 FIX: split into domain keywords vs path keywords
    #
    _domain_keywords = [
        "verify", "secure", "update", "suspended", "alert",
        "confirm", "unlock", "winner", "banking", "support",
        "restore", "recover", "claim", "urgent", "warning",
    ]
    _path_keywords = [
        "login", "signin", "verify", "account", "update",
        "secure", "confirm", "password", "suspend", "unlock",
        "recover", "billing", "payment", "restore",
    ]
    _brand_keywords = [
        "paypal", "amazon", "apple", "microsoft", "google",
        "facebook", "instagram", "netflix", "ebay", "dropbox",
        "chatgpt", "openai", "linkedin", "github", "binance", "twitter"
    ]

    features["keyword_count_in_domain"] = sum(
        1 for kw in _domain_keywords if kw in host_lower
    )
    features["keyword_count_in_path"] = sum(
        1 for kw in _path_keywords if kw in (path + query).lower()
    )
    features["brand_keyword_in_domain"] = int(
        any(b in host_lower for b in _brand_keywords)
    )

    # Combined score (domain keywords weighted more — stronger signal)
    features["total_keyword_score"] = (
        features["keyword_count_in_domain"] * 2 +
        features["keyword_count_in_path"]
    )
    features["has_suspicious_keyword"] = 1 if features["total_keyword_score"] > 0 else 0

    # ── 5. Protocol ───────────────────────────────────────────
    features["is_https"]  = 1 if parsed.scheme == "https" else 0
    features["has_port"]  = 1 if parsed.port   else 0

    # ── 6. Path Features ──────────────────────────────────────
    features["path_depth"] = len([p for p in path.split("/") if p])
    features["has_exe_extension"] = 1 if path.lower().endswith(
        (".exe", ".php", ".js", ".bat", ".scr")
    ) else 0

    # FIX 10 — redirect / token obfuscation in query string
    features["has_redirect_param"] = int(
        any(k in query.lower() for k in ["redirect", "return_to", "next", "goto", "redir"])
    )
    features["has_token_param"] = int(
        any(k in query.lower() for k in ["token", "session", "auth", "key"])
    )

    # ── 7. Ratios ─────────────────────────────────────────────
    url_len = len(full_url) or 1
    features["digit_ratio"]        = features["num_digits_in_url"] / url_len
    features["special_char_ratio"]  = (
        features["num_hyphens"] + features["num_underscores"] + features["num_percent"]
    ) / url_len
    features["hyphen_domain_ratio"] = features["num_hyphens_in_domain"] / (len(host) or 1)
    features["suspicious_keyword_count"] = (
        features["keyword_count_in_domain"]
        + features["keyword_count_in_path"]
    )
    return features


def get_feature_names() -> list:
    sample = extract_features("http://example.com")
    return list(sample.keys())


# ── Self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        # (url, expected_label, description)
        ("https://www.google.com",                                  "Legit",    "simple legit"),
        ("https://accounts.google.com/signin",                      "Legit",    "legit login page"),
        ("https://www.facebook.com/login",                          "Legit",    "legit /login"),
        ("https://www.paypal.com/myaccount/summary",                "Legit",    "legit /account"),
        ("https://www.t-mobile.com",                                "Legit",    "legit hyphen domain"),
        ("https://aws-portal.amazon.com",                           "Legit",    "legit subdomain+hyphen"),
        ("https://myaccount.google.com/security",                   "Legit",    "legit account subdomain"),
        ("http://paypal-secure-login.verify-account.com/update",    "Phishing", "classic phish"),
        ("http://192.168.1.1/login.php",                            "Phishing", "IP-based"),
        ("https://paypa1.com/login/secure/verify",                  "Phishing", "digit sub (HTTPS)"),
        ("https://arnazon-orders.com/account/verify",               "Phishing", "typosquat (HTTPS)"),
        ("http://paypal.verify-account-now.com/update",             "Phishing", "brand subdomain abuse"),
        ("http://google-account-verify.login-secure.tk",            "Phishing", "suspicious TLD .tk"),
        ("http://account-suspended-amazon-verify.ml/restore",       "Phishing", "suspicious TLD .ml"),
        ("https://chatgpt.com/",                                    "Legit",    "legit brand exact match"),
        ("https://secure-chase-bank.credential-steal.com/login",    "Phishing", "tricky HTTPS phish"),
    ]

    print("=" * 70)
    print("  Feature Extractor v2 — Self Test")
    print("=" * 70)

    keys_to_show = [
        "is_https", "has_ip_address", "has_suspicious_tld",
        "brand_in_domain", "domain_has_digit",
        "is_lookalike_domain", "brand_similarity_score",
        "keyword_count_in_domain", "keyword_count_in_path",
        "num_hyphens_in_domain", "num_subdomains",
        "has_redirect_param",
    ]

    header = f"  {'URL':<48} {'Exp':8}"
    for k in keys_to_show:
        header += f" {k[:6]:>6}"
    print(header)
    print("  " + "-" * (48 + 8 + len(keys_to_show) * 7))

    for url, label, desc in test_cases:
        f = extract_features(url)
        row = f"  {url[:47]:<48} {label:8}"
        for k in keys_to_show:
            row += f" {f[k]:>6}"
        print(row)

    print("\n  All features for one URL (paypa1.com phishing):")
    f = extract_features("https://paypa1.com/login/secure/verify")
    for k, v in f.items():
        bar = "#" * int(v * 10) if isinstance(v, float) else ""
        print(f"    {k:<35} = {v}  {bar}")