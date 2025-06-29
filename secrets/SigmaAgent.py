#!/usr/bin/env python3
"""
🚀 Sigma Rule Automation Agent
Author: Kwaw Fletcher Frimpong
Purpose: Automates the creation, enhancement, validation, and PR submission of Sigma detection rules based on CVEs.
Supports multiple platforms: Sigma, Azure Sentinel, CrowdStrike, and SentinelOne.
Uses OpenAI API for intelligent rule generation.
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
        
        # Use environment variable for token if available, otherwise use config
        self.token = os.environ.get("GITHUB_TOKEN") or self.config.get("github_token")
        if not self.token:
            print("⚠️  Warning: No GitHub token found in environment or config")
            print("   Set GITHUB_TOKEN environment variable or add github_token to config")
        else:
            print(f"🔑 Token found: {len(self.token)} characters")
            print(f"🔑 Token starts with: {self.token[:10]}...")
        
        # OpenAI API key
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        if not self.openai_api_key:
            print("⚠️  Warning: No OpenAI API key found in environment")
            print("   Set OPENAI_API_KEY environment variable for AI-powered rule generation")
        else:
            print(f"🤖 OpenAI API key found: {len(self.openai_api_key)} characters")
        
        self.github_user = self.config["github_user"]
        self.github_repo = self.config["github_repo"]
        self.auto_submit = self.config.get("auto_submit", False)
        
        print(f"📁 Repository path: {self.repo_path}")
        print(f"👤 Author: {self.author}")
        print(f"👤 GitHub user: {self.github_user}")
        print(f"📦 GitHub repo: {self.github_repo}")
        print(f"🚀 Auto submit: {self.auto_submit}")

    def generate_ai_rule(self, cve_id, desc, refs, platform="sigma"):
        """Generate AI-powered detection rule using OpenAI API"""
        if not self.openai_api_key:
            print("⚠️  No OpenAI API key available, using template-based generation")
            return None
            
        try:
            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json"
            }
            
            # Create platform-specific prompts
            if platform == "sigma":
                prompt = f"""Generate a sophisticated Sigma detection rule for CVE {cve_id}.

CVE Description: {desc}

References: {', '.join(refs)}

Create a Sigma rule that:
1. Uses appropriate logsource (Windows Sysmon, Linux auditd, etc.)
2. Has realistic detection criteria based on the vulnerability
3. Includes proper fields, false positives, and severity level
4. Follows Sigma rule best practices
5. Is specific to the vulnerability described

Return only the YAML content, no explanations."""
                
            elif platform == "sentinel":
                prompt = f"""Generate an Azure Sentinel KQL query for CVE {cve_id}.

CVE Description: {desc}

References: {', '.join(refs)}

Create a KQL query that:
1. Uses appropriate data sources (Sysmon, SecurityEvent, etc.)
2. Has realistic detection criteria based on the vulnerability
3. Includes proper time filtering and data projection
4. Uses KQL best practices and syntax
5. Is specific to the vulnerability described

Return only the KQL query, no explanations."""
                
            elif platform == "crowdstrike":
                prompt = f"""Generate a CrowdStrike Falcon query for CVE {cve_id}.

CVE Description: {desc}

References: {', '.join(refs)}

Create a Falcon query that:
1. Uses appropriate event types (ProcessRollup2, NetworkConnectIP4, etc.)
2. Has realistic detection criteria based on the vulnerability
3. Includes proper time filtering and data formatting
4. Uses SPL syntax correctly
5. Is specific to the vulnerability described

Return only the SPL query, no explanations."""
                
            elif platform == "sentinelone":
                prompt = f"""Generate a SentinelOne SQL query for CVE {cve_id}.

CVE Description: {desc}

References: {', '.join(refs)}

Create a SQL query that:
1. Uses appropriate tables and columns
2. Has realistic detection criteria based on the vulnerability
3. Includes proper time filtering and data selection
4. Uses SQL syntax correctly
5. Is specific to the vulnerability described

Return only the SQL query, no explanations."""
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert specializing in detection rule creation. Generate precise, actionable detection rules."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 1000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_generated_content = result["choices"][0]["message"]["content"].strip()
                print(f"🤖 AI-generated {platform} rule successfully")
                return ai_generated_content
            else:
                print(f"❌ OpenAI API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error calling OpenAI API: {e}")
            return None

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
        
        # Try AI generation first
        ai_rule = self.generate_ai_rule(cve_id, desc, refs, "sigma")
        if ai_rule:
            try:
                # Parse the AI-generated YAML
                rule = yaml.safe_load(ai_rule)
                # Ensure required fields are present
                rule.setdefault("id", str(uuid.uuid4()))
                rule.setdefault("status", "experimental")
                rule.setdefault("author", self.author)
                rule.setdefault("date", datetime.now().strftime("%Y/%m/%d"))
                rule.setdefault("tags", [f"cve.{cve_id.lower().replace('-', '.')}"])
                return rule
            except yaml.YAMLError as e:
                print(f"⚠️  Failed to parse AI-generated YAML: {e}")
        
        # Fallback to template-based generation
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

    def generate_sentinel_rule(self, cve_id):
        """Generate Azure Sentinel KQL query"""
        desc, refs = self.fetch_cve_metadata(cve_id)
        
        # Try AI generation first
        ai_query = self.generate_ai_rule(cve_id, desc, refs, "sentinel")
        if ai_query:
            kql_query = ai_query
        else:
            # Fallback to template-based generation
            kql_query = f"""
// Detection for {cve_id}
// Description: {desc}
// Author: {self.author}
// Date: {datetime.now().strftime("%Y/%m/%d")}

let timeframe = 1h;
let suspicious_processes = dynamic([
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe"
]);

Sysmon
| where TimeGenerated >= ago(timeframe)
| where EventID == 1
| where Process in~ (suspicious_processes)
| where CommandLine contains "suspicious" or CommandLine contains "malicious"
| project TimeGenerated, Computer, Process, CommandLine, ParentProcess, ParentCommandLine
| order by TimeGenerated desc
"""
        
        rule = {
            "title": f"Azure Sentinel Detection for {cve_id}",
            "description": desc,
            "author": self.author,
            "date": datetime.now().strftime("%Y/%m/%d"),
            "references": refs,
            "query": kql_query.strip(),
            "severity": "Medium",
            "tactics": ["Execution", "Persistence"],
            "techniques": ["T1059", "T1053"]
        }
        return rule

    def generate_crowdstrike_rule(self, cve_id):
        """Generate CrowdStrike Falcon query"""
        desc, refs = self.fetch_cve_metadata(cve_id)
        
        # Try AI generation first
        ai_query = self.generate_ai_rule(cve_id, desc, refs, "crowdstrike")
        if ai_query:
            falcon_query = ai_query
        else:
            # Fallback to template-based generation
            falcon_query = f"""
# CrowdStrike Falcon Detection for {cve_id}
# Description: {desc}
# Author: {self.author}
# Date: {datetime.now().strftime("%Y/%m/%d")}

event_simpleName=ProcessRollup2
| search "suspicious_process.exe" OR "malicious_activity.exe"
| eval timestamp=timestamp/1000
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(timestamp)
| table timestamp, ComputerName, FileName, CommandLine, ParentBaseFileName
| sort -timestamp
"""
        
        rule = {
            "title": f"CrowdStrike Falcon Detection for {cve_id}",
            "description": desc,
            "author": self.author,
            "date": datetime.now().strftime("%Y/%m/%d"),
            "references": refs,
            "query": falcon_query.strip(),
            "severity": "Medium",
            "platform": "Windows",
            "detection_type": "Process Execution"
        }
        return rule

    def generate_sentinelone_rule(self, cve_id):
        """Generate SentinelOne query"""
        desc, refs = self.fetch_cve_metadata(cve_id)
        
        # Try AI generation first
        ai_query = self.generate_ai_rule(cve_id, desc, refs, "sentinelone")
        if ai_query:
            sentinelone_query = ai_query
        else:
            # Fallback to template-based generation
            sentinelone_query = f"""
// SentinelOne Detection for {cve_id}
// Description: {desc}
// Author: {self.author}
// Date: {datetime.now().strftime("%Y/%m/%d")}

SELECT 
    eventTime,
    agentId,
    agentName,
    processName,
    processCommandLine,
    parentProcessName,
    parentProcessCommandLine
FROM events 
WHERE eventType = "Process Creation"
    AND (processName LIKE "%suspicious%" OR processName LIKE "%malicious%")
    AND eventTime >= NOW() - INTERVAL 1 HOUR
ORDER BY eventTime DESC
"""
        
        rule = {
            "title": f"SentinelOne Detection for {cve_id}",
            "description": desc,
            "author": self.author,
            "date": datetime.now().strftime("%Y/%m/%d"),
            "references": refs,
            "query": sentinelone_query.strip(),
            "severity": "Medium",
            "platform": "Windows",
            "event_type": "Process Creation"
        }
        return rule

    def save_sigma_rule(self, rule):
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', rule["title"]).lower()
        filename = f"win_{safe_title}_{rule['id'][:8]}.yml"
        
        # Use absolute path for rules/Sigma directory
        if self.repo_path.is_absolute():
            rule_path = self.repo_path / "rules" / "Sigma" / filename
        else:
            # If relative path, make it absolute from current working directory
            rule_path = Path.cwd() / self.repo_path / "rules" / "Sigma" / filename
        
        print(f"📁 Creating directory: {rule_path.parent}")
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 Saving rule to: {rule_path}")
        with open(rule_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(rule, f, sort_keys=False, allow_unicode=True)
        
        print(f"✅ Saved rule at {rule_path}")
        print(f"📄 File exists: {rule_path.exists()}")
        print(f"📄 File size: {rule_path.stat().st_size if rule_path.exists() else 'N/A'} bytes")
        
        return filename, rule_path

    def save_sentinel_rule(self, rule):
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', rule["title"]).lower()
        filename = f"sentinel_{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.kql"
        
        # Create sentinel directory
        if self.repo_path.is_absolute():
            rule_path = self.repo_path / "rules" / "sentinel" / filename
        else:
            rule_path = Path.cwd() / self.repo_path / "rules" / "sentinel" / filename
        
        print(f"📁 Creating directory: {rule_path.parent}")
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 Saving Sentinel rule to: {rule_path}")
        
        # Create a formatted KQL file with metadata
        content = f"""// {rule['title']}
// Description: {rule['description']}
// Author: {rule['author']}
// Date: {rule['date']}
// Severity: {rule['severity']}
// References: {', '.join(rule['references'])}

{rule['query']}
"""
        
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        print(f"✅ Saved Sentinel rule at {rule_path}")
        return filename, rule_path

    def save_crowdstrike_rule(self, rule):
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', rule["title"]).lower()
        filename = f"crowdstrike_{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.falcon"
        
        # Create crowdstrike directory
        if self.repo_path.is_absolute():
            rule_path = self.repo_path / "rules" / "crowdstrike" / filename
        else:
            rule_path = Path.cwd() / self.repo_path / "rules" / "crowdstrike" / filename
        
        print(f"📁 Creating directory: {rule_path.parent}")
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 Saving CrowdStrike rule to: {rule_path}")
        
        # Create a formatted Falcon query file with metadata
        content = f"""# {rule['title']}
# Description: {rule['description']}
# Author: {rule['author']}
# Date: {rule['date']}
# Severity: {rule['severity']}
# Platform: {rule['platform']}
# References: {', '.join(rule['references'])}

{rule['query']}
"""
        
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        print(f"✅ Saved CrowdStrike rule at {rule_path}")
        return filename, rule_path

    def save_sentinelone_rule(self, rule):
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', rule["title"]).lower()
        filename = f"sentinelone_{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        
        # Create sentinelone directory
        if self.repo_path.is_absolute():
            rule_path = self.repo_path / "rules" / "sentinelone" / filename
        else:
            rule_path = Path.cwd() / self.repo_path / "rules" / "sentinelone" / filename
        
        print(f"📁 Creating directory: {rule_path.parent}")
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 Saving SentinelOne rule to: {rule_path}")
        
        # Create a formatted SQL query file with metadata
        content = f"""-- {rule['title']}
-- Description: {rule['description']}
-- Author: {rule['author']}
-- Date: {rule['date']}
-- Severity: {rule['severity']}
-- Platform: {rule['platform']}
-- References: {', '.join(rule['references'])}

{rule['query']}
"""
        
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        print(f"✅ Saved SentinelOne rule at {rule_path}")
        return filename, rule_path

    def commit_and_push(self, files_to_commit, branch):
        print(f"🔄 Switching to repository: {self.repo_path}")
        os.chdir(self.repo_path)
        
        print(f"🌿 Creating branch: {branch}")
        subprocess.run(["git", "checkout", "-b", branch])
        
        # Add all files to git
        for filename, rule_path in files_to_commit:
            # Determine the correct target path based on filename
            if filename.startswith("sentinel_") and filename.endswith(".kql"):
                target_path = Path("rules") / "sentinel" / filename
            elif filename.startswith("crowdstrike_") and filename.endswith(".falcon"):
                target_path = Path("rules") / "crowdstrike" / filename
            elif filename.startswith("sentinelone_") and filename.endswith(".sql"):
                target_path = Path("rules") / "sentinelone" / filename
            else:
                # Default to main rules directory for Sigma rules
                target_path = Path("rules") / filename
            
            print(f"📁 Target path: {target_path}")
            print(f"📁 Source path: {rule_path}")
            
            # If source and target are the same file, just use the target path
            if rule_path.resolve() == target_path.resolve():
                print(f"📄 File already in correct location, using: {target_path}")
            else:
                # Create the directory if it doesn't exist
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy the file to the correct location
                shutil.copy2(rule_path, target_path)
                print(f"📄 File copied to: {target_path}")
            
            print(f"📄 File exists: {target_path.exists()}")
            print(f"📝 Adding file to git: {target_path}")
            subprocess.run(["git", "add", str(target_path)])
        
        print(f"💬 Committing changes")
        commit_message = f"new: Multi-platform detection rules - auto-generated for {len(files_to_commit)} platforms"
        subprocess.run(["git", "commit", "-m", commit_message])
        
        print(f"🚀 Pushing to remote")
        subprocess.run(["git", "push", "origin", branch])

    def create_pull_request(self, branch, title, body):
        # First, test the token by making a simple API call
        headers = {"Authorization": f"token {self.token}"}
        test_url = f"https://api.github.com/user"
        
        print(f"🧪 Testing token with API call to: {test_url}")
        test_response = requests.get(test_url, headers=headers)
        if test_response.status_code == 200:
            user_info = test_response.json()
            print(f"✅ Token is valid! Authenticated as: {user_info.get('login', 'Unknown')}")
        else:
            print(f"❌ Token test failed: {test_response.status_code} - {test_response.text}")
            return None
        
        # Now create the pull request
        pr_data = {
            "title": title,
            "head": f"{self.github_user}:{branch}",
            "base": "master",
            "body": body
        }
        
        print(f"📝 Creating PR with data: {pr_data}")
        r = requests.post(
            f"https://api.github.com/repos/{self.github_user}/{self.github_repo}/pulls",
            headers=headers, json=pr_data
        )
        if r.status_code == 201:
            print(f"🎉 PR created: {r.json()['html_url']}")
            return r.json()['html_url']
        else:
            print(f"❌ Failed to create PR: {r.status_code} - {r.text}")
            return None

    def validate_sigma_rule(self, rule):
        """Validate Sigma rule structure and content"""
        required_fields = ["title", "id", "status", "description", "author", "date", "logsource", "detection"]
        missing_fields = [field for field in required_fields if field not in rule]
        
        if missing_fields:
            print(f"⚠️  Missing required fields in Sigma rule: {missing_fields}")
            return False
        
        # Validate logsource structure
        if not isinstance(rule.get("logsource"), dict):
            print("⚠️  Logsource must be a dictionary")
            return False
        
        # Validate detection structure
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            print("⚠️  Detection must be a dictionary")
            return False
        
        if "selection" not in detection and "condition" not in detection:
            print("⚠️  Detection must contain selection and condition")
            return False
        
        print("✅ Sigma rule validation passed")
        return True

    def validate_query_syntax(self, query, platform):
        """Basic syntax validation for platform-specific queries"""
        if not query or not query.strip():
            print(f"⚠️  Empty {platform} query")
            return False
        
        # Basic syntax checks
        if platform == "sentinel" and "|" not in query:
            print("⚠️  KQL query should contain pipe operators")
            return False
        elif platform == "crowdstrike" and "|" not in query:
            print("⚠️  SPL query should contain pipe operators")
            return False
        elif platform == "sentinelone" and "SELECT" not in query.upper():
            print("⚠️  SQL query should contain SELECT statement")
            return False
        
        print(f"✅ {platform} query syntax validation passed")
        return True

    def run(self, cve_id):
        print(f"🚀 Generating multi-platform detection rules for {cve_id}")
        
        # Generate rules for all platforms
        sigma_rule = self.generate_sigma_rule(cve_id)
        sentinel_rule = self.generate_sentinel_rule(cve_id)
        crowdstrike_rule = self.generate_crowdstrike_rule(cve_id)
        sentinelone_rule = self.generate_sentinelone_rule(cve_id)
        
        # Validate rules if enabled
        if self.config.get("rule_validation", True):
            print("\n🔍 Validating generated rules...")
            if not self.validate_sigma_rule(sigma_rule):
                print("❌ Sigma rule validation failed")
                return None
            
            if not self.validate_query_syntax(sentinel_rule["query"], "sentinel"):
                print("❌ Sentinel query validation failed")
                return None
            
            if not self.validate_query_syntax(crowdstrike_rule["query"], "crowdstrike"):
                print("❌ CrowdStrike query validation failed")
                return None
            
            if not self.validate_query_syntax(sentinelone_rule["query"], "sentinelone"):
                print("❌ SentinelOne query validation failed")
                return None
        
        # Save all rules
        files_to_commit = []
        
        print(f"\n📝 Generating Sigma rule...")
        sigma_filename, sigma_path = self.save_sigma_rule(sigma_rule)
        files_to_commit.append((sigma_filename, sigma_path))
        
        print(f"\n📝 Generating Azure Sentinel rule...")
        sentinel_filename, sentinel_path = self.save_sentinel_rule(sentinel_rule)
        files_to_commit.append((sentinel_filename, sentinel_path))
        
        print(f"\n📝 Generating CrowdStrike rule...")
        crowdstrike_filename, crowdstrike_path = self.save_crowdstrike_rule(crowdstrike_rule)
        files_to_commit.append((crowdstrike_filename, crowdstrike_path))
        
        print(f"\n📝 Generating SentinelOne rule...")
        sentinelone_filename, sentinelone_path = self.save_sentinelone_rule(sentinelone_rule)
        files_to_commit.append((sentinelone_filename, sentinelone_path))

        if self.auto_submit:
            branch = f"auto/multi_platform_{sigma_rule['id'][:6]}"
            self.commit_and_push(files_to_commit, branch)
            title = f"new: Multi-platform detection rules for {cve_id}"
            body = f"""Auto-generated detection rules for {cve_id}

## Generated Rules:
- **Sigma**: {sigma_filename}
- **Azure Sentinel**: {sentinel_filename}
- **CrowdStrike**: {crowdstrike_filename}
- **SentinelOne**: {sentinelone_filename}

## Description:
{sigma_rule['description']}

## References:
""" + "\n".join([f"- {ref}" for ref in sigma_rule['references']])
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
