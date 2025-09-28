# whitelist.py
# ------------------------------------------------
# Utility module to load and manage whitelisted domains

import json

WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r") as f:
            data = json.load(f)
            return data.get("domains", [])
    except FileNotFoundError:
        # fallback default list
        return ["paypal.com", "google.com", "microsoft.com"]


if __name__ == "__main__":
    print("Whitelisted domains:", load_whitelist())
