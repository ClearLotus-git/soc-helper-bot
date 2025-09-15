import os
import json
import urllib.request

# ----------------------------
# Auto-download MITRE ATT&CK dataset
# ----------------------------
def load_mitre_data(path="cti/enterprise-attack.json"):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        print("[INFO] Downloading MITRE ATT&CK dataset...")
        urllib.request.urlretrieve(url, path)

    with open(path, "r", encoding="utf-8") as f:
        mitre_data = json.load(f)

    techniques = {}
    for obj in mitre_data.get("objects", []):
        if obj.get("type") == "attack-pattern" and "external_references" in obj:
            for ref in obj["external_references"]:
                if ref.get("source_name") == "mitre-attack":
                    techniques[ref["external_id"]] = {
                        "name": obj.get("name", "Unknown"),
                        "description": obj.get("description", "No description available."),
                        "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
                    }
    return techniques


# ----------------------------
# Load playbooks.json
# ----------------------------
def load_playbooks(path="playbooks.json"):
    if not os.path.exists(path):
        print("[ERROR] playbooks.json not found.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ----------------------------
# Enrich playbook with MITRE
# ----------------------------
def enrich_playbook(playbook, techniques):
    tid = playbook.get("technique_id")
    if tid in techniques:
        mitre_info = techniques[tid]
        playbook["technique_name"] = mitre_info["name"]
        playbook["description"] = mitre_info["description"]
        playbook["tactics"] = mitre_info["tactics"]
    return playbook


# ----------------------------
# SOC Helper Main Logic
# ----------------------------
def soc_helper(query, playbooks, techniques):
    for pb in playbooks:
        if pb["keyword"].lower() in query.lower():
            pb = enrich_playbook(pb, techniques)

            print(f"\nMITRE Technique: {pb.get('technique_id', 'N/A')} - {pb.get('technique_name', 'Unknown')}")
            print(f"\nDescription: {pb.get('description', '')[:250]}...\n")
            print(f"Tactics: {', '.join(pb.get('tactics', []))}")
            print(f"\nRelevant Logs: {', '.join(pb.get('logs', []))}")
            print("\nInvestigation Steps:")
            for i, step in enumerate(pb.get('steps', []), 1):
                print(f"  {i}. {step}")
            return
    print("[INFO] No matching playbook found. Consider updating playbooks.json.")


# ----------------------------
# Main entrypoint
# ----------------------------
if __name__ == "__main__":
    playbooks = load_playbooks()
    techniques = load_mitre_data()

    if playbooks and techniques:
        query = input("Enter alert/log description: ")
        soc_helper(query, playbooks, techniques)
