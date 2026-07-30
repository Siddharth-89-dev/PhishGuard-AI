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
    "reddit.com"
}

def is_whitelisted(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = urlparse(url).netloc.lower()

    if host.startswith("www."):
        host = host[4:]

    print("HOST:", host)

    for domain in WHITELIST:
        if host == domain or host.endswith("." + domain):
            print("WHITELIST MATCH:", domain)
            return True

    print("NO MATCH")
    return False