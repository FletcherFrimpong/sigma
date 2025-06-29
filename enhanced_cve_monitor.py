#!/usr/bin/env python3
"""
Enhanced CVE Monitor with Advanced Differentiators
Goes beyond traditional vulnerability management by providing:
- AI-powered threat intelligence integration
- Behavioral-based detection rules
- Custom threat hunting queries
- Industry-specific analysis
- Automated response playbooks
"""

import os
import re
import json
import yaml
import sqlite3
import requests
import openai
from datetime import datetime, timedelta
from pathlib import Path
import logging

class EnhancedCVEMonitor:
    def __init__(self, db_path="cve_database.db"):
        self.db_path = db_path
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        self.setup_database()
        self.setup_logging()
        
        # Enhanced threat intelligence sources
        self.threat_intel_sources = {
            'mitre_attack': 'https://attack.mitre.org/api/',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            'alienvault_otx': 'https://otx.alienvault.com/api/v1/',
            'ibm_xforce': 'https://api.xforce.ibmcloud.com/'
        }
        
        # Industry-specific templates
        self.industry_templates = {
            'healthcare': {
                'keywords': ['hipaa', 'medical', 'patient', 'healthcare', 'pharma'],
                'compliance': ['HIPAA', 'HITECH', 'FDA'],
                'assets': ['medical_devices', 'patient_data', 'clinical_systems']
            },
            'financial': {
                'keywords': ['banking', 'financial', 'payment', 'credit', 'insurance'],
                'compliance': ['PCI-DSS', 'SOX', 'GLBA'],
                'assets': ['payment_systems', 'customer_data', 'trading_platforms']
            },
            'government': {
                'keywords': ['government', 'federal', 'state', 'military', 'defense'],
                'compliance': ['FISMA', 'FedRAMP', 'NIST'],
                'assets': ['classified_systems', 'citizen_data', 'infrastructure']
            }
        }

    def setup_logging(self):
        """Setup enhanced logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(message)s',
            handlers=[
                logging.FileHandler('enhanced_cve_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        """Setup enhanced database with additional tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced CVE table with threat intelligence
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified TEXT,
                threat_actors TEXT,
                attack_techniques TEXT,
                exploit_availability TEXT,
                industry_impact TEXT,
                behavioral_patterns TEXT,
                hunting_queries TEXT,
                response_playbook TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threat intelligence correlation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                threat_actor TEXT,
                malware_family TEXT,
                attack_technique TEXT,
                confidence_score REAL,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES enhanced_cves (cve_id)
            )
        ''')
        
        # Industry-specific analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS industry_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                industry TEXT,
                impact_level TEXT,
                compliance_requirements TEXT,
                affected_assets TEXT,
                mitigation_strategies TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES enhanced_cves (cve_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def analyze_cve_with_ai_context(self, cve_id, description, refs):
        """Enhanced CVE analysis with AI-powered threat intelligence"""
        if not self.openai_api_key:
            self.logger.warning("OpenAI API key not available for enhanced analysis")
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            prompt = f"""
            Analyze CVE {cve_id} with advanced threat intelligence context:
            
            Description: {description}
            References: {', '.join(refs)}
            
            Provide analysis in JSON format with the following structure:
            {{
                "threat_actors": ["list of known threat actors who might exploit this"],
                "attack_techniques": ["MITRE ATT&CK techniques this CVE enables"],
                "exploit_availability": "high/medium/low - likelihood of public exploits",
                "industry_impact": {{
                    "healthcare": "critical/high/medium/low",
                    "financial": "critical/high/medium/low", 
                    "government": "critical/high/medium/low"
                }},
                "behavioral_patterns": ["suspicious behaviors to monitor"],
                "hunting_queries": ["threat hunting queries for this CVE"],
                "response_playbook": {{
                    "automated_actions": ["immediate automated responses"],
                    "manual_actions": ["manual response procedures"],
                    "notifications": ["who to notify and when"]
                }}
            }}
            
            Focus on practical, actionable intelligence for security operations.
            """
            
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000
            )
            
            analysis = json.loads(response.choices[0].message.content)
            self.logger.info(f"Enhanced AI analysis completed for {cve_id}")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis for {cve_id}: {e}")
            return None

    def generate_behavioral_detection_rules(self, cve_id, analysis):
        """Generate behavioral-based detection rules"""
        if not analysis:
            return None
        
        behavioral_patterns = analysis.get('behavioral_patterns', [])
        
        # Generate Sigma behavioral rule
        sigma_rule = {
            "title": f"Behavioral Detection - {cve_id}",
            "description": f"Detects behavioral patterns associated with {cve_id} exploitation",
            "tags": ["cve", "behavioral", "threat-hunting"],
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "process_creation": {
                        "parent_process": ["cmd.exe", "powershell.exe"],
                        "process": ["*suspicious*", "*payload*", "*exploit*"]
                    }
                },
                "condition": "selection"
            },
            "falsepositives": ["Legitimate security testing", "Authorized penetration testing"],
            "level": "high"
        }
        
        # Add behavioral patterns to the rule
        if behavioral_patterns:
            sigma_rule["detection"]["selection"]["process_creation"]["process"].extend(
                [pattern.lower() for pattern in behavioral_patterns]
            )
        
        return sigma_rule

    def generate_threat_hunting_queries(self, cve_id, analysis):
        """Generate custom threat hunting queries"""
        if not analysis:
            return None
        
        hunting_queries = analysis.get('hunting_queries', [])
        
        queries = {
            "sigma": f"""
# Threat Hunting Query for {cve_id}
title: Threat Hunting - {cve_id}
description: Hunting query for {cve_id} exploitation patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_creation:
      process: ["*suspicious*", "*payload*"]
      parent_process: ["cmd.exe", "powershell.exe"]
  condition: selection
""",
            "kql": f"""
// Azure Sentinel Hunting Query for {cve_id}
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where ProcessCommandLine contains "suspicious" or ProcessCommandLine contains "payload"
| where InitiatingProcessFileName in ("cmd.exe", "powershell.exe")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
""",
            "spl": f"""
# CrowdStrike Falcon Hunting Query for {cve_id}
| inputlookup process_rollup2
| search CommandLine="*suspicious*" OR CommandLine="*payload*"
| search ParentProcessName="cmd.exe" OR ParentProcessName="powershell.exe"
| table _time ComputerName CommandLine ParentProcessName
| sort - _time
""",
            "sql": f"""
-- SentinelOne Hunting Query for {cve_id}
SELECT 
    timestamp,
    hostname,
    process_name,
    command_line,
    parent_process
FROM process_events 
WHERE timestamp >= NOW() - INTERVAL '7 days'
    AND (command_line LIKE '%suspicious%' OR command_line LIKE '%payload%')
    AND parent_process IN ('cmd.exe', 'powershell.exe')
ORDER BY timestamp DESC;
"""
        }
        
        return queries

    def create_response_playbook(self, cve_id, analysis):
        """Generate automated response playbook"""
        if not analysis:
            return None
        
        playbook = analysis.get('response_playbook', {})
        
        yaml_playbook = {
            "playbook_name": f"CVE-{cve_id}-Response",
            "description": f"Automated response playbook for {cve_id}",
            "severity": "high",
            "triggers": [f"Detection of {cve_id} exploitation"],
            "automated_actions": playbook.get('automated_actions', []),
            "manual_actions": playbook.get('manual_actions', []),
            "notifications": playbook.get('notifications', []),
            "escalation": {
                "level_1": "Security Analyst",
                "level_2": "Security Engineer", 
                "level_3": "CISO"
            }
        }
        
        return yaml_playbook

    def analyze_industry_impact(self, cve_id, analysis):
        """Analyze industry-specific impact"""
        if not analysis:
            return None
        
        industry_impact = analysis.get('industry_impact', {})
        
        industry_analysis = {}
        for industry, impact in industry_impact.items():
            template = self.industry_templates.get(industry, {})
            
            industry_analysis[industry] = {
                "impact_level": impact,
                "compliance_requirements": template.get('compliance', []),
                "affected_assets": template.get('assets', []),
                "mitigation_strategies": self.generate_mitigation_strategies(industry, impact)
            }
        
        return industry_analysis

    def generate_mitigation_strategies(self, industry, impact):
        """Generate industry-specific mitigation strategies"""
        strategies = {
            "healthcare": {
                "critical": ["Immediate system isolation", "Patient safety assessment", "HIPAA breach notification"],
                "high": ["Enhanced monitoring", "Access control review", "Staff training"],
                "medium": ["Regular patching", "Vulnerability scanning", "Security awareness"],
                "low": ["Standard patching", "Documentation update"]
            },
            "financial": {
                "critical": ["Transaction monitoring", "Customer notification", "Regulatory reporting"],
                "high": ["Enhanced fraud detection", "Account monitoring", "Compliance review"],
                "medium": ["Security controls", "Risk assessment", "Staff training"],
                "low": ["Standard controls", "Documentation"]
            }
        }
        
        return strategies.get(industry, {}).get(impact, ["Standard mitigation procedures"])

    def save_enhanced_analysis(self, cve_id, description, refs, analysis):
        """Save enhanced analysis to database"""
        if not analysis:
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO enhanced_cves 
                (cve_id, description, threat_actors, attack_techniques, exploit_availability, 
                 industry_impact, behavioral_patterns, hunting_queries, response_playbook)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                json.dumps(analysis.get('threat_actors', [])),
                json.dumps(analysis.get('attack_techniques', [])),
                analysis.get('exploit_availability', 'unknown'),
                json.dumps(analysis.get('industry_impact', {})),
                json.dumps(analysis.get('behavioral_patterns', [])),
                json.dumps(analysis.get('hunting_queries', [])),
                json.dumps(analysis.get('response_playbook', {}))
            ))
            
            conn.commit()
            self.logger.info(f"Enhanced analysis saved for {cve_id}")
            
        except Exception as e:
            self.logger.error(f"Error saving enhanced analysis for {cve_id}: {e}")
        finally:
            conn.close()

    def generate_enhanced_rules(self, cve_id, analysis, platform="all"):
        """Generate enhanced detection rules with behavioral patterns"""
        rules = {}
        
        if platform in ["all", "sigma"]:
            behavioral_rule = self.generate_behavioral_detection_rules(cve_id, analysis)
            if behavioral_rule:
                rules["sigma"] = behavioral_rule
        
        if platform in ["all", "hunting"]:
            hunting_queries = self.generate_threat_hunting_queries(cve_id, analysis)
            if hunting_queries:
                rules["hunting"] = hunting_queries
        
        if platform in ["all", "playbook"]:
            response_playbook = self.create_response_playbook(cve_id, analysis)
            if response_playbook:
                rules["playbook"] = response_playbook
        
        return rules

    def run_enhanced_monitoring(self, days=7):
        """Run enhanced CVE monitoring with threat intelligence"""
        self.logger.info(f"Starting enhanced CVE monitoring for {days} days")
        
        # Fetch CVEs (using existing logic)
        # For demonstration, we'll use a sample CVE
        sample_cve = {
            "id": "CVE-2023-1234",
            "description": "A critical vulnerability in web application framework",
            "refs": ["https://example.com/cve-2023-1234"]
        }
        
        # Enhanced analysis
        analysis = self.analyze_cve_with_ai_context(
            sample_cve["id"], 
            sample_cve["description"], 
            sample_cve["refs"]
        )
        
        if analysis:
            # Save enhanced analysis
            self.save_enhanced_analysis(
                sample_cve["id"],
                sample_cve["description"], 
                sample_cve["refs"],
                analysis
            )
            
            # Generate enhanced rules
            enhanced_rules = self.generate_enhanced_rules(sample_cve["id"], analysis)
            
            # Save rules to files
            self.save_enhanced_rules(sample_cve["id"], enhanced_rules)
            
            self.logger.info(f"Enhanced monitoring completed for {sample_cve['id']}")
            return enhanced_rules
        
        return None

    def save_enhanced_rules(self, cve_id, rules):
        """Save enhanced rules to appropriate directories"""
        base_dir = Path("enhanced_rules")
        base_dir.mkdir(exist_ok=True)
        
        for rule_type, rule_content in rules.items():
            if rule_type == "sigma":
                rule_dir = base_dir / "sigma"
                rule_dir.mkdir(exist_ok=True)
                
                with open(rule_dir / f"{cve_id}_behavioral.yml", 'w') as f:
                    yaml.dump(rule_content, f, default_flow_style=False)
            
            elif rule_type == "hunting":
                hunting_dir = base_dir / "hunting"
                hunting_dir.mkdir(exist_ok=True)
                
                for platform, query in rule_content.items():
                    ext = {"sigma": "yml", "kql": "kql", "spl": "spl", "sql": "sql"}[platform]
                    with open(hunting_dir / f"{cve_id}_hunting.{ext}", 'w') as f:
                        f.write(query)
            
            elif rule_type == "playbook":
                playbook_dir = base_dir / "playbooks"
                playbook_dir.mkdir(exist_ok=True)
                
                with open(playbook_dir / f"{cve_id}_response.yml", 'w') as f:
                    yaml.dump(rule_content, f, default_flow_style=False)

    def show_enhanced_stats(self):
        """Show enhanced statistics with threat intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        print("\n=== Enhanced CVE Monitoring Statistics ===")
        
        # Basic stats
        cursor.execute("SELECT COUNT(*) FROM enhanced_cves")
        total_cves = cursor.fetchone()[0]
        print(f"Total Enhanced CVEs: {total_cves}")
        
        # Threat actor analysis
        cursor.execute("SELECT threat_actors FROM enhanced_cves WHERE threat_actors IS NOT NULL")
        threat_actors = cursor.fetchall()
        
        if threat_actors:
            print(f"CVEs with Threat Actor Attribution: {len(threat_actors)}")
        
        # Industry impact analysis
        cursor.execute("SELECT industry_impact FROM enhanced_cves WHERE industry_impact IS NOT NULL")
        industry_impacts = cursor.fetchall()
        
        if industry_impacts:
            print(f"CVEs with Industry Impact Analysis: {len(industry_impacts)}")
        
        # Exploit availability
        cursor.execute("SELECT exploit_availability, COUNT(*) FROM enhanced_cves GROUP BY exploit_availability")
        exploit_stats = cursor.fetchall()
        
        print("\nExploit Availability Analysis:")
        for availability, count in exploit_stats:
            print(f"  {availability}: {count} CVEs")
        
        conn.close()

def main():
    """Main function for enhanced CVE monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced CVE Monitor with Threat Intelligence")
    parser.add_argument("--enhanced-monitor", action="store_true", help="Run enhanced monitoring")
    parser.add_argument("--enhanced-stats", action="store_true", help="Show enhanced statistics")
    parser.add_argument("--days", type=int, default=7, help="Days to monitor")
    
    args = parser.parse_args()
    
    monitor = EnhancedCVEMonitor()
    
    if args.enhanced_monitor:
        monitor.run_enhanced_monitoring(args.days)
    elif args.enhanced_stats:
        monitor.show_enhanced_stats()
    else:
        print("Enhanced CVE Monitor")
        print("Use --enhanced-monitor to run enhanced monitoring")
        print("Use --enhanced-stats to show enhanced statistics")

if __name__ == "__main__":
    main() 