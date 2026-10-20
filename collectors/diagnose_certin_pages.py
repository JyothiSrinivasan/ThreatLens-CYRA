
import re
import html
import requests
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "data" / "raw" / "certin_page_diagnostics.txt"

ADVISORY_IDS = [
    "CIAD-2024-0050",
    "CIAD-2025-0048",
    "CIAD-2026-0039",
    "CIAD-2026-0042",
]

BASE_URL = (
    "https://www.cert-in.org.in/s2cMainServlet"
    "?pageid=PUBVLNOTES02&VLCODE="
)

HEADERS = {
    "User-Agent": "ThreatLens-CTI-Student-Project/1.0"
}


def main():
    results = []

    for advisory_id in ADVISORY_IDS:
        url = BASE_URL + advisory_id
        print(f"Checking {advisory_id}...")

        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=20,
            )
            response.raise_for_status()

            text = html.unescape(
                re.sub(r"<[^>]+>", " ", response.text)
            )
            text = re.sub(r"\s+", " ", text)

            index = text.find(advisory_id)
            excerpt = (
                text[max(0, index):max(0, index) + 1200]
                if index >= 0
                else text[:700]
            )

            results.append(
                f"\n--- {advisory_id} | HTTP {response.status_code} ---\n"
                f"URL: {url}\n{excerpt}\n"
            )

        except requests.RequestException as exc:
            results.append(
                f"\n--- {advisory_id} ---\n"
                f"Request failed: {type(exc).__name__}\n"
            )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(results), encoding="utf-8")

    print("\nDiagnostics saved to:")
    print(OUTPUT)


if __name__ == "__main__":
    main()
