
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "raw" / "certin_advisories.json"
OUTPUT = ROOT / "data" / "processed" / "certin_advisories_cleaned.json"


def clean_advisory_text(text):
    if not text:
        return ""

    # Remove JavaScript function blocks from the webpage template.
    text = re.sub(
        r"function\s+hidestatus\s*\(\s*\).*?(?=Accessibility Options|Description)",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"function\s+Clickheretoprint\s*\(\s*\).*",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"function\s+confirmToExternalLink\s*\(\s*\).*",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"function\s+convertHTMLtoText\s*\(.*?(?=Description|Summary|Impact)",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove a known CSS fragment without discarding adjacent content.
    text = re.sub(r"#text\s+a\s*\{[^}]*\}", " ", text)

    # Remove common navigation labels.
    boilerplate_phrases = [
        "Accessibility Options | Sitemap | Contact Us",
        "Website Policies | Terms of Use | Help",
    ]
    for phrase in boilerplate_phrases:
        text = text.replace(phrase, " ")

    # Normalize whitespace while retaining advisory content.
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text

def main():
    records = json.loads(INPUT.read_text(encoding="utf-8"))
    cleaned_records = []
    shortened = 0
    empty_texts = 0

    for record in records:
        cleaned = dict(record)
        original_text = record.get("text", "")
        cleaned_text = clean_advisory_text(original_text)
        cleaned["text_original_length"] = len(original_text)
        cleaned["text"] = cleaned_text
        cleaned["text_cleaned_length"] = len(cleaned_text)
        cleaned["text_cleaning_method"] = "rule_based_template_and_footer_removal"
        cleaned_records.append(cleaned)

        if len(cleaned_text) < len(original_text):
            shortened += 1
        if not cleaned_text:
            empty_texts += 1

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(cleaned_records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("CERT-In text cleaning completed.")
    print("Input advisories:", len(records))
    print("Output advisories:", len(cleaned_records))
    print("Records shortened:", shortened)
    print("Records with empty cleaned text:", empty_texts)
    print("Output file:", OUTPUT)


if __name__ == "__main__":
    main()
