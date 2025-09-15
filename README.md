# SOC Helper Bot

A lightweight Python tool that assists SOC analysts in mapping alerts or log descriptions to MITRE ATT&CK techniques, relevant log sources, and step-by-step investigation playbooks.

The bot automatically downloads the official MITRE ATT&CK dataset (enterprise-attack.json) if not already present, ensuring you always have up-to-date mappings without cloning the full CTI repo.

## Features

- Maps alert keywords to MITRE ATT&CK technique IDs, names, and descriptions
- Suggests log sources (Sysmon, Windows Security, etc.) for validation
- Provides step-by-step investigation guidance
- Auto-fetches the MITRE dataset on first run
- Easy to extend by editing playbooks.json

## Example Usage

`Enter alert/log description: suspicious powershell activity`

## Output

```
MITRE Technique: T1059.001 - PowerShell

Description: Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface...

Tactics: execution

Relevant Logs: Sysmon Event ID 1, Security Log 4688

Investigation Steps:
  1. Check parent process of PowerShell execution
  2. Look for obfuscation (Base64, IEX, long strings)
  3. Pivot on user account and machine for related activity
```

## Installation

1. Clone the repository:


```
git clone https://github.com/ClearLotus-git/soc-helper-bot.git
cd soc-helper-bot
```
2. Install dependencies:

```
pip install -r requirements.txt
```

3. Run the bot:

```
python soc_helper.py
```
Enter a log description or alert keyword when prompted.
The bot will return the mapped MITRE ATT&CK technique, logs to check, and investigation steps.

## Extending the Playbooks:

You can add your own playbooks to playbooks.json.
Each playbook must include:

- keyword – keyword to match against log/alert descriptions
- technique_id – MITRE ATT&CK technique (e.g., T1059.001)
- logs – list of relevant log sources
- steps – ordered investigation steps

## Example:

```
[
  {
    "keyword": "mimikatz",
    "technique_id": "T1003.001",
    "logs": ["Sysmon Event ID 10", "Security Log 4624"],
    "steps": [
      "Check for suspicious LSASS access",
      "Look for process dump utilities",
      "Hunt for credential extraction attempts across hosts"
    ]
  }
]
```

## Requirements

Python 3.8+
requests (for dataset retrieval if you decide to use requests instead of urllib)

## License
MIT License – free to use, modify, and share.







