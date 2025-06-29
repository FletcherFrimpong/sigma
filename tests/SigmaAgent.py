#!/usr/bin/env python3
"""
🚀 Sigma Rule Automation Agent
Author: Kwaw Fletcher Frimpong
Purpose: Automates the creation, enhancement, validation, and PR submission of Sigma detection rules based on CVEs.
"""

import os
import re
import uuid
import json
import yaml
import shutil
import requests
import subprocess
from pathlib import Path
from datetime import datetime

class SigmaRuleBot:
    def __init__(self, config_file="sigma_config.json"):
        with open(config_file) as f:
            self.config = json.load(f)

        self.repo_path = Path(self.config["sigma_repo_path"])
        self.author = self.config.get("author_name", "SigmaBot")
        self.token = self.config["github_token"]
        self.github_user = self.config["github_user"]
        self.github_repo = self.config["github_repo"]
        self.auto_submit = self.config.get("auto_submit", False)

    def fetch_cve_metadata(self, cve_id):
        print(f"🔍 Fetching CVE metadata for {cve_id}...")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                vuln = r.json()["vulnerabilities"][0]["cve"]
                desc = vuln.get("descriptions", [{}])[0].get("value", "")
                refs = [r["url"] for r in vuln.get("references", [])][:3]
                return desc, refs
        except Exception as e:
            print(f"⚠️  Error: {e}")
        return "", []

    def generate_sigma_rule(self, cve_id):
        desc, refs = self.fetch_cve_metadata(cve_id)
        rule = {
            "title": f"Detection for {cve_id}",
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": desc,
            "references": refs,
            "author": self.author,
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
                    "Image|endswith": "\\malicious.exe"
                },
                "condition": "selection"
            },
            "fields": ["Image", "CommandLine", "ParentImage"],
            "falsepositives": ["Legitimate testing tools"],
            "level": "medium"
        }
        return rule

    def save_sigma_rule(self, rule):
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', rule["title"]).lower()
        filename = f"win_{safe_title}_{rule['id'][:8]}.yml"
        rule_path = self.repo_path / "rules" / filename
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        with open(rule_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(rule, f, sort_keys=False, allow_unicode=True)
        print(f"✅ Saved rule at {rule_path}")
        return filename, rule_path

    def commit_and_push(self, filename, rule_path, branch):
        os.chdir(self.repo_path)
        subprocess.run(["git", "checkout", "-b", branch])
        shutil.move(str(rule_path), f"rules/{filename}")
        subprocess.run(["git", "add", f"rules/{filename}"])
        subprocess.run(["git", "commit", "-m", f"new: {filename} - auto-generated rule"])
        subprocess.run(["git", "push", "origin", branch])

    def create_pull_request(self, branch, title, body):
        headers = {"Authorization": f"token {self.token}"}
        pr_data = {
            "title": title,
            "head": f"{self.github_user}:{branch}",
            "base": "master",
            "body": body
        }
        r = requests.post(
            f"https://api.github.com/repos/SigmaHQ/{self.github_repo}/pulls",
            headers=headers, json=pr_data
        )
        if r.status_code == 201:
            print(f"🎉 PR created: {r.json()['html_url']}")
            return r.json()['html_url']
        else:
            print(f"❌ Failed to create PR: {r.status_code} - {r.text}")
            return None

    def run(self, cve_id):
        rule = self.generate_sigma_rule(cve_id)
        filename, rule_path = self.save_sigma_rule(rule)

        if self.auto_submit:
            branch = f"auto/sigma_rule_{rule['id'][:6]}"
            self.commit_and_push(filename, rule_path, branch)
            title = f"new: {rule['title']}"
            body = f"Auto-generated Sigma rule for {cve_id}\n\n{rule['description']}\n\nReferences:\n" + "\n".join(rule['references'])
            return self.create_pull_request(branch, title, body)
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True)
    args = parser.parse_args()
    bot = SigmaRuleBot()
    bot.run(args.cve)
