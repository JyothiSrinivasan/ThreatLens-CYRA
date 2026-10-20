
import os
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

misp_url = os.getenv("MISP_URL")
misp_key = os.getenv("MISP_API_KEY")
verify_cert = os.getenv("MISP_VERIFY_CERT", "true").lower() == "true"

if not misp_url or not misp_key or misp_key == "paste_your_misp_auth_key_here":
    raise SystemExit("MISP_URL or MISP_API_KEY is missing in .env")

try:
    misp = PyMISP(misp_url, misp_key, ssl=verify_cert, tool="ThreatLens")
    print("PyMISP object created.")
    print("Checking MISP version...")

    version = misp.misp_instance_version
    print("MISP connection successful.")
    print("MISP version:", version)
    
except Exception as exc:
    print("MISP connection failed.")
    print("Error type:", type(exc).__name__)
    print("Check that MISP is running and your .env settings are correct.")
