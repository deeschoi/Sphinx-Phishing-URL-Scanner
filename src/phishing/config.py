"""Project-wide constants. Feature order matches Training_Dataset.csv exactly."""

import os
from pathlib import Path

RANDOM_STATE = 42
N_SPLITS = 5
TEST_SIZE = 0.20

# Repo root: src/phishing/config.py -> parents[2]
def _path_from_env(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


def _first_existing(*candidates: Path) -> Path:
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


# Defaults assume an editable checkout (src/phishing/config.py -> parents[2]).
# When the package is pip-installed elsewhere — in a container, for instance —
# that inference is wrong, so every path can be overridden by environment.
PROJECT_ROOT = _path_from_env("PHISHING_ROOT", Path(__file__).resolve().parents[2])
DATA_PATH = _path_from_env(
    "PHISHING_DATA",
    _first_existing(
        PROJECT_ROOT / "research" / "datasets" / "Training_Dataset.csv",
        PROJECT_ROOT / "datasets" / "Training_Dataset.csv",
        PROJECT_ROOT / "Training_Dataset.csv",
    ),
)
ARTIFACTS_DIR = _path_from_env("PHISHING_ARTIFACTS_DIR", PROJECT_ROOT / "artifacts")
REPORTS_DIR = _path_from_env("PHISHING_REPORTS_DIR", PROJECT_ROOT / "reports")
FIGURES_DIR = REPORTS_DIR / "figures"


def ensure_dirs() -> None:
    """Create every directory the pipeline writes to."""
    for path in (ARTIFACTS_DIR, REPORTS_DIR, FIGURES_DIR):
        path.mkdir(parents=True, exist_ok=True)

# 30 predictors in CSV column order. Models consume this order positionally.
FEATURE_COLUMNS = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

TARGET_COLUMN = "Result"

# URL-string features: computable offline from the URL text alone.
TIER_A = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
]

# Page-content features: require fetching and parsing HTML (no JS execution).
TIER_B = [
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
]

# Infrastructure features still obtainable in 2026 (TLS / WHOIS / DNS / port).
TIER_C = [
    "SSLfinal_State",
    "Domain_registeration_length",
    "port",
    "Abnormal_URL",
    "age_of_domain",
    "DNSRecord",
]

# Reputation features whose original data sources are gone or impractical.
UNAVAILABLE_2026 = [
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

DEAD_FEATURE_REASON = {
    "web_traffic": "Alexa Rank was retired in 2022.",
    "Page_Rank": "Google Toolbar PageRank was shut down in 2016.",
    "Google_Index": "Requires a paid Search API; not queried at scan time.",
    "Links_pointing_to_page": "Inbound-link counts need a backlink index that is not queried.",
    "Statistical_report": "Original feature used 2012 PhishTank / StopBadware blocklists.",
}

DEPLOYABLE_FEATURES = [c for c in FEATURE_COLUMNS if c not in UNAVAILABLE_2026]

TIER_A_PLUS_B = TIER_A + TIER_B
TIER_A_PLUS_B_PLUS_C = TIER_A + TIER_B + TIER_C

assert len(FEATURE_COLUMNS) == 30
assert len(TIER_A) == 8
assert len(TIER_B) == 11
assert len(TIER_C) == 6
assert len(UNAVAILABLE_2026) == 5
assert len(DEPLOYABLE_FEATURES) == 25
assert set(TIER_A + TIER_B + TIER_C + UNAVAILABLE_2026) == set(FEATURE_COLUMNS)

# Encoding used throughout the UCI dataset and the live extractor.
PHISHING = -1
SUSPICIOUS = 0
LEGITIMATE = 1

# Recoded target: 1 = phishing (positive class), 0 = legitimate.
POSITIVE_CLASS = 1
NEGATIVE_CLASS = 0

# Default classification threshold before calibration / F1 search.
DEFAULT_THRESHOLD = 0.5

# Risk bands applied to calibrated phishing probability.
RISK_BANDS = [
    (0.00, 0.25, "low"),
    (0.25, 0.50, "medium"),
    (0.50, 0.75, "high"),
    (0.75, 1.01, "critical"),
]

# What a live scan must do to obtain each feature. Drives the deployment-tier
# scenarios in research/analysis/04 and the scan-coverage reporting in the UI.
SOURCE = {
    **{f: "url_only" for f in TIER_A},
    **{f: "http" for f in TIER_B},
    "SSLfinal_State": "tls",
    "port": "portscan",
    "Domain_registeration_length": "dns_whois",
    "Abnormal_URL": "dns_whois",
    "age_of_domain": "dns_whois",
    "DNSRecord": "dns_whois",
    **{f: "dead" for f in UNAVAILABLE_2026},
}

assert set(SOURCE) == set(FEATURE_COLUMNS)

# Features whose observed phishing rate moves opposite to the documented
# encoding. Identified by the encoding audit in research/analysis/03; kept here because
# the scanner flags them in its explanations.
REVERSED_FEATURES = [
    "Shortining_Service",
    "double_slash_redirecting",
    "Domain_registeration_length",
    "HTTPS_token",
    "Abnormal_URL",
    "Redirect",
    "Links_pointing_to_page",
]

# Features with an identical phishing rate at every encoded value.
NO_SIGNAL_FEATURES = ["Favicon", "popUpWidnow", "Iframe"]

FEATURE_LABELS = {
    "having_IP_Address": "IP address in hostname",
    "URL_Length": "URL length",
    "Shortining_Service": "URL shortener",
    "having_At_Symbol": "@ in the URL",
    "double_slash_redirecting": "Late // in the URL",
    "Prefix_Suffix": "Hyphen in the domain",
    "having_Sub_Domain": "Subdomain depth",
    "SSLfinal_State": "Certificate / HTTPS",
    "Domain_registeration_length": "Domain registration length",
    "Favicon": "Favicon host",
    "port": "Non-standard port",
    "HTTPS_token": "https in the domain name",
    "Request_URL": "External page resources",
    "URL_of_Anchor": "Off-domain or empty anchors",
    "Links_in_tags": "External meta/script/link tags",
    "SFH": "Form handler",
    "Submitting_to_email": "Mailto / mail() form",
    "Abnormal_URL": "Host vs WHOIS registrant",
    "Redirect": "Redirect count",
    "on_mouseover": "Status-bar spoofing",
    "RightClick": "Right-click disabled",
    "popUpWidnow": "Popup script",
    "Iframe": "Invisible iframe",
    "age_of_domain": "Domain age",
    "DNSRecord": "DNS record",
    "web_traffic": "Alexa traffic rank",
    "Page_Rank": "Toolbar PageRank",
    "Google_Index": "Google Index",
    "Links_pointing_to_page": "Inbound links",
    "Statistical_report": "2012 blocklist hit",
}

VALUE_MEANING = {
    "having_IP_Address": {-1: "Hostname is a raw IP", 1: "Hostname is a domain"},
    "URL_Length": {-1: "75+ characters", 0: "54–74 characters", 1: "Under 54 characters"},
    "Shortining_Service": {-1: "Uses a shortener", 1: "Not a known shortener"},
    "having_At_Symbol": {-1: "Contains @", 1: "No @"},
    "double_slash_redirecting": {-1: "// appears late in the URL", 1: "No late //"},
    "Prefix_Suffix": {-1: "Domain contains a hyphen", 1: "No hyphen in the domain"},
    "having_Sub_Domain": {-1: "Multiple subdomains", 0: "One subdomain", 1: "Bare domain"},
    "SSLfinal_State": {
        -1: "No HTTPS or untrusted / short-lived cert",
        0: "HTTPS, but issuer or age is weak",
        1: "Trusted issuer, cert at least a year old",
    },
    "Domain_registeration_length": {-1: "Expires within a year", 1: "Expires after a year"},
    "Favicon": {-1: "Favicon served off-domain", 1: "Favicon on the same domain"},
    "port": {-1: "Preferred-closed port is open", 1: "Standard web ports only"},
    "HTTPS_token": {-1: "https appears in the domain", 1: "No https token in the domain"},
    "Request_URL": {-1: "Many resources loaded off-domain", 1: "Most resources on-domain"},
    "URL_of_Anchor": {
        -1: "Most links point off-domain or nowhere",
        0: "A mix of on- and off-domain links",
        1: "Most links stay on-domain",
    },
    "Links_in_tags": {
        -1: "Many external tags",
        0: "Some external tags",
        1: "Tags mostly on-domain",
    },
    "SFH": {
        -1: "Empty or off-domain form handler",
        0: "Handler is about:blank",
        1: "Handler is on-domain",
    },
    "Submitting_to_email": {-1: "Form submits by email", 1: "No mailto / mail()"},
    "Abnormal_URL": {-1: "Host does not match WHOIS", 1: "Host matches WHOIS"},
    "Redirect": {0: "At most one redirect", 1: "Several redirects"},
    "on_mouseover": {-1: "Status-bar spoofing in the source", 1: "No status-bar spoof"},
    "RightClick": {-1: "Right-click handler in the source", 1: "Right-click not blocked"},
    "popUpWidnow": {-1: "window.open in the source", 1: "No popup script"},
    "Iframe": {-1: "Invisible iframe present", 1: "No iframe"},
    "age_of_domain": {-1: "Domain younger than six months", 1: "Domain at least six months old"},
    "DNSRecord": {-1: "No DNS record", 1: "DNS record exists"},
    "web_traffic": {-1: "Not in the Alexa top 100k", 0: "Ranked below 100k", 1: "Alexa top 100k"},
    "Page_Rank": {-1: "PageRank under 0.2", 1: "PageRank at least 0.2"},
    "Google_Index": {-1: "Not indexed by Google", 1: "Indexed by Google"},
    "Links_pointing_to_page": {-1: "No inbound links", 0: "1–2 inbound links", 1: "More than 2"},
    "Statistical_report": {-1: "Host on a 2012 blocklist", 1: "Not on a 2012 blocklist"},
}

GENERIC_VALUE = {-1: "phishing indicator", 0: "suspicious / unknown", 1: "legitimate"}

# One record per feature: display label, documented value meanings, and how a
# live scan would obtain it.
FEATURE_INFO = {
    feature: {
        "label": FEATURE_LABELS[feature],
        "values": VALUE_MEANING.get(feature, GENERIC_VALUE),
        "source": SOURCE[feature],
        "reversed": feature in REVERSED_FEATURES,
    }
    for feature in FEATURE_COLUMNS
}

# ---------------------------------------------------------------------------
# PhiUSIIL (Prasad & Chandra, 2023/24) — the served scanner model
# ---------------------------------------------------------------------------
# Raw URL + HTML table. Label in the CSV is 1 = legitimate, 0 = phishing;
# loaders invert that to match this package (1 = phishing).
PHIUSIIL_PATH = _path_from_env(
    "PHISHING_PHIUSIIL", PROJECT_ROOT / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

# Columns that leak the label or are identifiers, never fed to a model.
PHIUSIIL_DROP = [
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title",
    "URLSimilarityIndex",  # 100 for every legitimate row
    "URLCharProb",  # derived per-URL prior we cannot reproduce at scan time
]

# Shared hosting where anyone can publish under someone else's apex. Kits use
# these because the parent domain is already trusted and TLS is free.
#
# NOT a model feature. In PhiUSIIL these suffixes cover 22,478 phishing rows
# and exactly 1 legitimate row, so a model trained on them learns
# "platform ⇒ phishing" outright: with IsFreeHostingPlatform as an input the
# URL-only estimator scored real docs sites (docs.github.io, nextjs.vercel.app)
# at p ≈ 0.999 and ranked the feature second by importance. It is kept as a
# scanner routing hint instead — it gates the URL-disagreement fallback so a
# platform-hosted kit cannot be talked down to legitimate.
PHIUSIIL_PLATFORM_SUFFIXES = [
    "web.app",
    "firebaseapp.com",
    "repl.co",
    "workers.dev",
    "dweb.link",
    "godaddysites.com",
    "duckdns.org",
    "webwave.dev",
    "weebly.com",
    "glitch.me",
    "wixsite.com",
    "yolasite.com",
    "myportfolio.com",
    "github.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "herokuapp.com",
]

# URL-string features: no network. IsHTTPS is the scheme bit, not the 2012
# SSLfinal_State (trusted issuer + cert older than a year).
PHIUSIIL_URL_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "CharContinuationRate",
    "TLDLegitimateProb",
]

# Page-source features. These replace Alexa / PageRank / inbound-link counts:
# social links, copyright, JS/CSS/image volume, and title↔domain match are
# living proxies for "does this look like an established site?"
PHIUSIIL_HTML_FEATURES = [
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]

# Static markup on JS-rendered sites. PhiUSIIL crawled complete homepages;
# GitHub / Visa / Ramp shells have almost no anchors and little HTML, which
# the model reads as a phishing kit. At scan time these are imputed when the
# page looks like a shell.
PHIUSIIL_SPA_LINK_FEATURES = [
    "NoOfExternalRef",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "LineOfCode",
]

# PhiUSIIL homepages were pretty-printed (legit 90th percentile ≈ 16k chars).
# Live minified HTML is often one 100k–1M character line, which overlaps the
# phishing-obfuscation tail. Scan-time values above this are treated as
# unmeasured and filled with the legitimate-class median.
PHIUSIIL_MINIFIED_LINE_CHARS = 20_000

PHIUSIIL_MODEL_FEATURES = PHIUSIIL_URL_FEATURES + PHIUSIIL_HTML_FEATURES

PHIUSIIL_FEATURE_LABELS = {
    "URLLength": "URL length",
    "DomainLength": "Hostname length",
    "IsDomainIP": "Hostname is a raw IP",
    "TLDLength": "TLD length",
    "NoOfSubDomain": "Subdomain depth",
    "HasObfuscation": "Percent-encoded characters",
    "NoOfObfuscatedChar": "Percent-encoded character count",
    "ObfuscationRatio": "Percent-encoding ratio",
    "NoOfLettersInURL": "Letters in the URL",
    "LetterRatioInURL": "Letter ratio",
    "NoOfDegitsInURL": "Digits in the URL",
    "DegitRatioInURL": "Digit ratio",
    "NoOfEqualsInURL": "Equals signs in the URL",
    "NoOfQMarkInURL": "Question marks in the URL",
    "NoOfAmpersandInURL": "Ampersands in the URL",
    "NoOfOtherSpecialCharsInURL": "Other special characters",
    "SpacialCharRatioInURL": "Special-character ratio",
    "IsHTTPS": "Uses HTTPS",
    "CharContinuationRate": "Uninterrupted character runs in the domain",
    "TLDLegitimateProb": "How common this TLD is among legitimate sites",
    "IsFreeHostingPlatform": "Free shared-hosting platform",
    "LineOfCode": "HTML line count",
    "LargestLineLength": "Longest HTML line",
    "HasTitle": "Has a title",
    "DomainTitleMatchScore": "Domain appears in the title",
    "URLTitleMatchScore": "URL appears in the title",
    "HasFavicon": "Has a favicon",
    "Robots": "Robots directives present",
    "IsResponsive": "Responsive viewport tag",
    "NoOfURLRedirect": "Redirect count",
    "NoOfSelfRedirect": "Same-site redirects",
    "HasDescription": "Has a description meta tag",
    "NoOfPopup": "Popup scripts",
    "NoOfiFrame": "Iframe count",
    "HasExternalFormSubmit": "Form posts off-domain",
    "HasSocialNet": "Social-network links",
    "HasSubmitButton": "Submit button",
    "HasHiddenFields": "Hidden form fields",
    "HasPasswordField": "Password field",
    "Bank": "Banking keywords",
    "Pay": "Payment keywords",
    "Crypto": "Crypto keywords",
    "HasCopyrightInfo": "Copyright notice",
    "NoOfImage": "Image count",
    "NoOfCSS": "Stylesheet count",
    "NoOfJS": "Script count",
    "NoOfSelfRef": "On-domain links",
    "NoOfEmptyRef": "Empty or javascript links",
    "NoOfExternalRef": "Off-domain links",
}

FEATURE_LABELS.update(PHIUSIIL_FEATURE_LABELS)

VALUE_MEANING.update(
    {
        "IsDomainIP": {0: "Hostname is a domain", 1: "Hostname is a raw IP"},
        "HasObfuscation": {0: "No percent-encoding", 1: "URL contains percent-encoding"},
        "IsHTTPS": {0: "HTTP (no TLS)", 1: "HTTPS"},
        "IsFreeHostingPlatform": {
            0: "Hosted on its own domain",
            1: "Published on free shared hosting (anyone can register a subdomain)",
        },
        "HasTitle": {0: "No title", 1: "Has a title"},
        "HasFavicon": {0: "No favicon", 1: "Has a favicon"},
        "Robots": {0: "No robots directives", 1: "Robots directives present"},
        "IsResponsive": {0: "No viewport tag", 1: "Responsive viewport tag"},
        "HasDescription": {0: "No description meta tag", 1: "Has a description"},
        "HasExternalFormSubmit": {0: "Forms stay on-domain", 1: "A form posts off-domain"},
        "HasSocialNet": {0: "No social-network links", 1: "Links out to social networks"},
        "HasSubmitButton": {0: "No submit button", 1: "Has a submit button"},
        "HasHiddenFields": {0: "No hidden fields", 1: "Has hidden form fields"},
        "HasPasswordField": {0: "No password field", 1: "Has a password field"},
        "Bank": {0: "No banking keywords", 1: "Banking keywords present"},
        "Pay": {0: "No payment keywords", 1: "Payment keywords present"},
        "Crypto": {0: "No crypto keywords", 1: "Crypto keywords present"},
        "HasCopyrightInfo": {0: "No copyright notice", 1: "Copyright notice present"},
    }
)

assert len(PHIUSIIL_MODEL_FEATURES) == 48
assert len(set(PHIUSIIL_MODEL_FEATURES)) == 48
assert set(PHIUSIIL_SPA_LINK_FEATURES) <= set(PHIUSIIL_HTML_FEATURES)
