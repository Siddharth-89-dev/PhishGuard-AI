import pandas as pd
import random

# ---------- CONFIG ----------
SIZE = 20000   # total dataset size

brands = ["google", "paypal", "amazon", "facebook", "bank", "apple"]
keywords = ["login", "verify", "secure", "update", "account", "signin"]
domains = ["google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com"]

# ---------- GENERATE PHISHING ----------
phishing_urls = []
for _ in range(SIZE // 2):
    url = f"http://{random.choice(keywords)}-{random.choice(brands)}-{random.randint(100,999)}.xyz"
    phishing_urls.append(url)

# ---------- GENERATE LEGIT ----------
legit_urls = []
for _ in range(SIZE // 2):
    url = f"https://{random.choice(domains)}/page{random.randint(1,100)}"
    legit_urls.append(url)

# ---------- CREATE DATAFRAME ----------
df_phish = pd.DataFrame({
    "url": phishing_urls,
    "label": "phishing"
})

df_legit = pd.DataFrame({
    "url": legit_urls,
    "label": "legitimate"
})

# ---------- MERGE ----------
df = pd.concat([df_legit, df_phish], ignore_index=True)

# Shuffle dataset
df = df.sample(frac=1).reset_index(drop=True)

# ---------- SAVE ----------
df.to_csv("phishing_dataset.csv", index=False)

print("✅ Dataset created: phishing_dataset.csv")
print("Total rows:", len(df))