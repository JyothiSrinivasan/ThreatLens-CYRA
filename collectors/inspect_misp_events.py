
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

print("Retrieving MISP events...")

response = misp.search(
    controller="events",
    return_format="json",
    metadata=True,
)

if isinstance(response, dict):
    events = response.get("response", response.get("Event", []))
else:
    events = response

if not isinstance(events, list):
    raise SystemExit(
        f"Unexpected event response: {type(response).__name__}"
    )

print("Events returned:", len(events))

for item in events:
    event = item.get("Event", item) if isinstance(item, dict) else {}
    print({
        "id": event.get("id"),
        "uuid": event.get("uuid"),
        "info": event.get("info"),
        "attribute_count": event.get("attribute_count"),
    })

print("Read-only event inspection complete.")
print("No events or attributes created.")
