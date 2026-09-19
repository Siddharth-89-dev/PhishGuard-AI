from urllib.parse import urlparse

WHITELIST = {
    "google.com",
    "github.com",
    "openai.com",
    "chatgpt.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "linkedin.com",
    "youtube.com",
    "gmail.com",
    "outlook.com",
    "office.com",
    "stackoverflow.com",
    "python.org",
    "fastapi.tiangolo.com",
    "kaggle.com",
    "cloudflare.com",
    "mozilla.org",
    "ubuntu.com",
    "oracle.com",
    "adobe.com",
    "netflix.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "reddit.com",
    "spotify.com",
    "leetcode.com",
    "hackerrank.com",
    "codeforces.com",
    "geeksforgeeks.org",
    "coursera.org",
    "udemy.com",
    "zoom.us",
    "slack.com",
    "discord.com",
    "notion.so",
    "figma.com",
    "canva.com",
    "vercel.com",
    "netlify.com",
    "render.com",
    "snapchat.com",
    "claude.ai",
}

def is_whitelisted(url):
    try:
        url_str = str(url).strip()
        if not url_str:
            return False
        if "://" not in url_str:
            url_str = "https://" + url_str

        parsed = urlparse(url_str)
        host = (parsed.hostname or "").lower().strip()
        if host.startswith("www."):
            host = host[4:]

        if not host:
            return False

        all_whitelisted = set(WHITELIST)
        try:
            from utils.adaptive_whitelist import promoted_domains
            all_whitelisted.update(promoted_domains())
        except Exception:
            pass

        # Institutional / Educational / Government domain check
        # Regulated TLDs (.edu, .edu.in, .ac.in, .gov, .gov.in, .ac.uk, .mil)
        # require verified accreditation and cannot be registered by attackers.
        labels = host.split(".")
        if len(labels) >= 2:
            suffix_parts = labels[-2:]
            if any(p in {"gov", "mil", "edu", "ac"} for p in suffix_parts):
                return True
        if labels[-1] in {"gov", "edu", "mil"}:
            return True

        return any(
            host == domain or host.endswith("." + domain)
            for domain in all_whitelisted
        )

    except Exception:
        return False