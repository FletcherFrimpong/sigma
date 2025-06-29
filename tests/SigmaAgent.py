#!/usr/bin/env python3
"""
Simplified Sigma Rule Automation Agent
Generates a basic Sigma rule for a given CVE ID using NVD data.
"""

import yaml
import json
import requests
import uuid
import re
import os
from datetime import datetime
from pathlib import Path

class SimpleSigmaAgent:
    def __init__(self, config_file="sigma_config.json"):
        self.config = self.load_config(config_file)
        self.repo_path = self.config.get("sigma_repo_path", ".")

    def load_config(self, config_file):
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                return json.load(f)
        return {}

    def get_cve_info(self, cve_id):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
                desc = vuln.get("descriptions", [{}])[0].get("value", "")
                refs = [ref["url"] for ref in vuln.get("references", [])]
                return desc, refs
        except Exception as e:
            print(f"Error: {e}")
        return "", []

    def generate_rule(self, cve_id):
        desc, refs = self.get_cve_info(cve_id)
        rule = {
            "title": f"Detection for {cve_id}",
            "id": str(uuid.uuid4()),
            "description": desc,
            "status": "experimental",
            "references": refs[:3],
            "author": "Sigma Bot",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "tags": [f"cve.{cve_id.lower().replace('-', '.')}"],
            "logsource": {
                "product": "windows",
                "service": "sysmon",
                "category": "process_creation"
            },
            "detection": {
                "selection": {
                    "EventID": 1,
                    "Image|endswith": "\\suspicious.exe"
                },
                "condition": "selection"
            },
            "fields": ["Image", "CommandLine"],
            "falsepositives": ["legitimate usage"],
            "level": "medium"
        }
        return rule

    def save_rule(self, rule):
        filename = f"win_{re.sub(r'[^a-zA-Z0-9]', '_', rule['title'].lower())}_{rule['id'][:8]}.yml"
        filepath = Path(self.repo_path) / "rules" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✅ Rule saved to: {filepath}")
        except Exception as e:
            print(f"Error saving rule: {e}")

    def run(self, cve_id):
        rule = self.generate_rule(cve_id)
        self.save_rule(rule)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True, help="CVE ID to generate rule for")
    args = parser.parse_args()

    agent = SimpleSigmaAgent()
    agent.run(args.cve)
