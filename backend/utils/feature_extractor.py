import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "paypal",
    "signin",
    "password",
    "confirm"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl",
    "goo.gl",
    "t.co",
    "is.gd",
    "ow.ly"
]


def extract_url_features(url):

    parsed = urlparse(url)

    hostname = parsed.netloc.lower()

    path = parsed.path

    query = parsed.query

    return [

        len(url),                              # 1

        len(hostname),                         # 2

        url.count("."),                        # 3

        url.count("-"),                        # 4

        url.count("_"),                        # 5

        url.count("@"),                        # 6

        url.count("?"),                        # 7

        url.count("="),                        # 8

        url.count("&"),                        # 9

        url.count("/"),                        # 10

        sum(c.isdigit() for c in url),         # 11

        sum(c.isdigit() for c in hostname),    # 12

        hostname.count("."),                   # 13

        int(parsed.scheme == "https"),         # 14

        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", hostname))),  # 15

        int(any(word in url.lower() for word in SUSPICIOUS_WORDS)),  #16

        int(any(short in hostname for short in SHORTENERS)),   #17

        len(path),                             #18

        len(query),                            #19

        int(hostname.startswith("www.")),      #20

    ]