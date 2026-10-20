
import os
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

url = os.getenv("MISP_URL")
key = os.getenv("MISP_API_KEY")
verify = os.getenv("MISP_VERIFY_CERT", "false").lower() == "true"

if not url or not key:
    raise SystemExit("MISP_URL or MISP_API_KEY is missing from .env")

misp = PyMISP(url, key, ssl=verify)

print("Testing MISP attribute search limits...")

for limit in (10, 50, 100):
    try:
        response = misp.search(
            controller="attributes",
            return_format="json",
            limit=limit,
            page=1,
        )

        if isinstance(response, dict):
            attributes = response.get("Attribute", [])
        elif isinstance(response, list):
            attributes = response
        else:
            attributes = []

        print(f"Requested limit: {limit}")
        print(f"Returned attributes: {len(attributes)}")

    except Exception as exc:
        print(f"Limit {limit} failed: {type(exc).__name__}: {exc}")

print("Diagnostic complete. No MISP changes made.")
