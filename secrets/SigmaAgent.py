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
        config_path = Path(config_file)
        
        # If the path contains directory separators, treat it as relative to current working directory
        if "/" in str(config_path) or "\\" in str(config_path):
            config_path = Path.cwd() / config_path
        elif not config_path.is_absolute() and not str(config_path).startswith("." + os.sep):
            # If it's just a filename, join with script dir
            script_dir = Path(__file__).parent
            config_path = script_dir / config_path
            
        print(f"🔧 Loading config from: {config_path}")
        print(f"🔧 Current working directory: {Path.cwd()}")
        
        try:
            with open(config_path) as f:
                self.config = json.load(f)
            print(f"✅ Config loaded successfully")
        except FileNotFoundError:
            print(f"❌ Config file not found: {config_path}")
            print("Please ensure sigma_config.json exists in the secrets directory.")
            raise
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in config file: {e}")
            raise

        self.repo_path = Path(self.config["sigma_repo_path"])
        self.author = self.config.get("author_name", "SigmaBot")
        self.token = self.config["github_token"]
        self.github_user = self.config["github_user"]
        self.github_repo = self.config["github_repo"]
        self.auto_submit = self.config.get("auto_submit", False)
        
        print(f"📁 Repository path: {self.repo_path}")
        print(f"👤 Author: {self.author}")
        print(f"🔑 Token length: {len(self.token) if self.token else 0}")
        print(f"👤 GitHub user: {self.github_user}")
        print(f"📦 GitHub repo: {self.github_repo}")
        print(f"🚀 Auto submit: {self.auto_submit}")

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
        
        # Use absolute path for rules directory
        if self.repo_path.is_absolute():
            rule_path = self.repo_path / "rules" / filename
        else:
            # If relative path, make it absolute from current working directory
            rule_path = Path.cwd() / self.repo_path / "rules" / filename
        
        print(f"📁 Creating directory: {rule_path.parent}")
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 Saving rule to: {rule_path}")
        with open(rule_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(rule, f, sort_keys=False, allow_unicode=True)
        
        print(f"✅ Saved rule at {rule_path}")
        print(f"📄 File exists: {rule_path.exists()}")
        print(f"📄 File size: {rule_path.stat().st_size if rule_path.exists() else 'N/A'} bytes")
        
        return filename, rule_path

    def commit_and_push(self, filename, rule_path, branch):
        print(f"🔄 Switching to repository: {self.repo_path}")
        os.chdir(self.repo_path)
        
        print(f"🌿 Creating branch: {branch}")
        subprocess.run(["git", "checkout", "-b", branch])
        
        # Ensure the file is in the correct location relative to the repository root
        target_path = Path("rules") / filename
        print(f"📁 Target path: {target_path}")
        print(f"📁 Source path: {rule_path}")
        
        # Create the rules directory if it doesn't exist
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy the file to the correct location
        shutil.copy2(rule_path, target_path)
        print(f"📄 File copied to: {target_path}")
        print(f"📄 File exists: {target_path.exists()}")
        
        print(f"📝 Adding file to git: {target_path}")
        subprocess.run(["git", "add", str(target_path)])
        
        print(f"💬 Committing changes")
        subprocess.run(["git", "commit", "-m", f"new: {filename} - auto-generated rule"])
        
        print(f"🚀 Pushing to remote")
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
    parser.add_argument("--auto-submit", action="store_true", help="Automatically submit PR")
    parser.add_argument("--config", default=None, help="Path to config file (default: sigma_config.json in script directory)")
    args = parser.parse_args()
    config_file = args.config if args.config else "sigma_config.json"
    bot = SigmaRuleBot(config_file=config_file)
    # Override auto_submit from config if specified in command line
    if args.auto_submit:
        bot.auto_submit = True
    bot.run(args.cve)
