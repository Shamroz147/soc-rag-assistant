import pandas as pd
import json
import re


from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent   
INPUT_PATH = PROJECT_ROOT / "data" / "mitre-attack" / "enterprise-attack.json"
OUTPUT_PATH = PROJECT_ROOT / "data" / "mitre_techniques.csv"


def load_attack_data():
    with open(INPUT_PATH, encoding="utf-8") as f:
        return json.load(f)



def get_technique_id(technique):
    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None



def clean_description(text):
    text = re.sub(r"\(Citation: [^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r" +", " ", text)
    return text.strip()


def parse_techniques(bundle):
    rows = []
    for obj in bundle["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated") == True:
            continue

        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]

        rows.append({
            "technique_id": get_technique_id(obj),
            "name": obj["name"],
            "tactics": ", ".join(tactics),
            "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
            "description": clean_description(obj.get("description", "")),
        })
        
    return rows


if __name__ == "__main__":
    rows = parse_techniques(load_attack_data())
    df = pd.DataFrame(rows)
    df.to_csv(OUTPUTPATH, index=False, encoding="utf-8")
    print(f"Saved {len(df)} techniques to {OUTPUTPATH}")