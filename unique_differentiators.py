#!/usr/bin/env python3
"""
Unique Differentiators for CVE Monitoring System
Implements features that make this system truly different from vendor solutions:
- Custom AI prompt engineering
- Rapid prototyping capabilities
- Organization-specific intelligence
- Integration hub functionality
- Community-driven features
"""

import os
import json
import yaml
import sqlite3
import openai
from datetime import datetime
from pathlib import Path
import logging

class UniqueDifferentiators:
    def __init__(self):
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        self.setup_logging()
        
        # Organization-specific configuration
        self.org_config = self.load_org_config()
        
        # Custom AI prompts for different scenarios
        self.custom_prompts = self.load_custom_prompts()
        
        # Integration configurations
        self.integrations = self.load_integrations()

    def setup_logging(self):
        """Setup logging for the unique differentiators"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def load_org_config(self):
        """Load organization-specific configuration"""
        config_path = Path("org_config.json")
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        else:
            # Default configuration - customize for your organization
            default_config = {
                "organization": {
                    "name": "Your Organization",
                    "industry": "technology",  # healthcare, financial, government, etc.
                    "size": "medium",  # small, medium, large
                    "risk_tolerance": "medium",  # low, medium, high
                    "compliance_requirements": ["SOX", "PCI-DSS"],
                    "geographic_regions": ["US", "EU"],
                    "technology_stack": ["AWS", "Azure", "Linux", "Windows"],
                    "security_tools": ["CrowdStrike", "SIEM", "Firewall"]
                },
                "threat_landscape": {
                    "primary_threats": ["ransomware", "phishing", "insider_threats"],
                    "targeted_assets": ["customer_data", "intellectual_property", "financial_systems"],
                    "known_threat_actors": ["APT29", "Lazarus Group"],
                    "attack_vectors": ["email", "web", "supply_chain"]
                },
                "custom_controls": {
                    "existing_detections": ["EDR", "SIEM", "Firewall"],
                    "response_capabilities": ["automated_isolation", "manual_investigation"],
                    "notification_channels": ["email", "slack", "teams"]
                }
            }
            
            # Save default config for customization
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config

    def load_custom_prompts(self):
        """Load custom AI prompts for different scenarios"""
        prompts_path = Path("custom_prompts.json")
        if prompts_path.exists():
            with open(prompts_path) as f:
                return json.load(f)
        else:
            # Default custom prompts - highly customizable
            default_prompts = {
                "cve_analysis": {
                    "basic": "Analyze CVE {cve_id} and provide basic detection logic.",
                    "advanced": """
                    Analyze CVE {cve_id} with the following context:
                    - Organization: {org_name} ({industry} industry)
                    - Risk tolerance: {risk_tolerance}
                    - Technology stack: {tech_stack}
                    - Compliance: {compliance}
                    
                    Provide:
                    1. Custom detection logic for our environment
                    2. Specific attack vectors relevant to our industry
                    3. Compliance impact assessment
                    4. Custom response procedures
                    5. Integration with our existing tools: {security_tools}
                    """,
                    "threat_hunting": """
                    Create threat hunting queries for CVE {cve_id} considering:
                    - Our specific threat landscape: {threats}
                    - Our targeted assets: {assets}
                    - Known threat actors: {actors}
                    - Our attack vectors: {vectors}
                    
                    Generate hunting queries that look for:
                    1. Pre-attack reconnaissance
                    2. Initial compromise attempts
                    3. Lateral movement patterns
                    4. Data exfiltration attempts
                    5. Persistence mechanisms
                    """
                },
                "response_automation": {
                    "playbook": """
                    Create an automated response playbook for CVE {cve_id} in our environment:
                    - Organization: {org_name}
                    - Existing controls: {controls}
                    - Response capabilities: {capabilities}
                    - Notification channels: {notifications}
                    
                    Include:
                    1. Immediate automated actions
                    2. Manual response procedures
                    3. Escalation procedures
                    4. Communication templates
                    5. Integration with our tools
                    """
                }
            }
            
            # Save default prompts for customization
            with open(prompts_path, 'w') as f:
                json.dump(default_prompts, f, indent=2)
            
            return default_prompts

    def load_integrations(self):
        """Load integration configurations"""
        integrations_path = Path("integrations.json")
        if integrations_path.exists():
            with open(integrations_path) as f:
                return json.load(f)
        else:
            # Default integration configurations
            default_integrations = {
                "siem": {
                    "type": "generic",
                    "endpoints": {
                        "alerts": "/api/alerts",
                        "rules": "/api/rules",
                        "incidents": "/api/incidents"
                    },
                    "authentication": "api_key"
                },
                "crowdstrike": {
                    "type": "falcon",
                    "endpoints": {
                        "detections": "/detects/queries/detects/v1",
                        "indicators": "/indicators/queries/iocs/v1",
                        "incidents": "/incidents/queries/incidents/v1"
                    },
                    "authentication": "oauth2"
                },
                "slack": {
                    "type": "notification",
                    "channels": ["#security-alerts", "#incident-response"],
                    "templates": {
                        "cve_alert": "🚨 New CVE detected: {cve_id} - {description}",
                        "incident_created": "📋 Incident created for {cve_id} - {severity}"
                    }
                },
                "email": {
                    "type": "notification",
                    "recipients": ["security@company.com", "it@company.com"],
                    "templates": {
                        "cve_report": "CVE Report: {cve_id} - {severity} severity"
                    }
                }
            }
            
            # Save default integrations for customization
            with open(integrations_path, 'w') as f:
                json.dump(default_integrations, f, indent=2)
            
            return default_integrations

    def generate_custom_cve_analysis(self, cve_id, description, refs):
        """Generate custom CVE analysis using organization-specific context"""
        if not self.openai_api_key:
            self.logger.warning("OpenAI API key not available")
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            # Get organization context
            org = self.org_config["organization"]
            threats = self.org_config["threat_landscape"]
            controls = self.org_config["custom_controls"]
            
            # Use custom prompt with organization context
            prompt = self.custom_prompts["cve_analysis"]["advanced"].format(
                cve_id=cve_id,
                org_name=org["name"],
                industry=org["industry"],
                risk_tolerance=org["risk_tolerance"],
                tech_stack=", ".join(org["technology_stack"]),
                compliance=", ".join(org["compliance_requirements"]),
                security_tools=", ".join(org["security_tools"]),
                threats=", ".join(threats["primary_threats"]),
                assets=", ".join(threats["targeted_assets"]),
                actors=", ".join(threats["known_threat_actors"]),
                vectors=", ".join(threats["attack_vectors"])
            )
            
            prompt += f"\n\nCVE Description: {description}\nReferences: {', '.join(refs)}"
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000
            )
            
            analysis = response.choices[0].message.content
            self.logger.info(f"Custom CVE analysis generated for {cve_id}")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in custom CVE analysis: {e}")
            return None

    def generate_threat_hunting_queries(self, cve_id, analysis):
        """Generate custom threat hunting queries based on organization context"""
        if not self.openai_api_key:
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            # Get threat landscape context
            threats = self.org_config["threat_landscape"]
            
            prompt = self.custom_prompts["cve_analysis"]["threat_hunting"].format(
                cve_id=cve_id,
                threats=", ".join(threats["primary_threats"]),
                assets=", ".join(threats["targeted_assets"]),
                actors=", ".join(threats["known_threat_actors"]),
                vectors=", ".join(threats["attack_vectors"])
            )
            
            prompt += f"\n\nCVE Analysis: {analysis}"
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1500
            )
            
            hunting_queries = response.choices[0].message.content
            self.logger.info(f"Custom threat hunting queries generated for {cve_id}")
            
            return hunting_queries
            
        except Exception as e:
            self.logger.error(f"Error generating hunting queries: {e}")
            return None

    def create_custom_response_playbook(self, cve_id, analysis):
        """Create custom response playbook for organization"""
        if not self.openai_api_key:
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            # Get organization context
            org = self.org_config["organization"]
            controls = self.org_config["custom_controls"]
            
            prompt = self.custom_prompts["response_automation"]["playbook"].format(
                cve_id=cve_id,
                org_name=org["name"],
                controls=", ".join(controls["existing_detections"]),
                capabilities=", ".join(controls["response_capabilities"]),
                notifications=", ".join(controls["notification_channels"])
            )
            
            prompt += f"\n\nCVE Analysis: {analysis}"
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1500
            )
            
            playbook = response.choices[0].message.content
            self.logger.info(f"Custom response playbook created for {cve_id}")
            
            return playbook
            
        except Exception as e:
            self.logger.error(f"Error creating response playbook: {e}")
            return None

    def generate_rapid_prototype_rules(self, cve_id, rule_type="sigma"):
        """Rapidly prototype detection rules for testing"""
        if not self.openai_api_key:
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            prompt = f"""
            Rapidly prototype a {rule_type} detection rule for CVE {cve_id}.
            
            Requirements:
            - Focus on quick implementation for testing
            - Include basic detection logic
            - Add comments for customization
            - Make it easy to modify and iterate
            
            Generate a working {rule_type} rule that can be immediately tested.
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=1000
            )
            
            prototype_rule = response.choices[0].message.content
            self.logger.info(f"Rapid prototype rule generated for {cve_id}")
            
            return prototype_rule
            
        except Exception as e:
            self.logger.error(f"Error generating prototype rule: {e}")
            return None

    def create_community_rule(self, cve_id, contributor, rule_type="sigma"):
        """Create community-contributed rules with attribution"""
        if not self.openai_api_key:
            return None
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            prompt = f"""
            Create a community-contributed {rule_type} rule for CVE {cve_id}.
            
            Contributor: {contributor}
            
            Requirements:
            - Include contributor attribution
            - Add community notes and context
            - Include testing recommendations
            - Add collaboration guidelines
            
            Make this rule suitable for community sharing and collaboration.
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1200
            )
            
            community_rule = response.choices[0].message.content
            self.logger.info(f"Community rule created for {cve_id} by {contributor}")
            
            return community_rule
            
        except Exception as e:
            self.logger.error(f"Error creating community rule: {e}")
            return None

    def save_custom_artifacts(self, cve_id, artifacts):
        """Save custom artifacts to organized directories"""
        base_dir = Path("custom_artifacts")
        base_dir.mkdir(exist_ok=True)
        
        cve_dir = base_dir / cve_id
        cve_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for artifact_type, content in artifacts.items():
            if artifact_type == "analysis":
                with open(cve_dir / f"{cve_id}_custom_analysis_{timestamp}.md", 'w') as f:
                    f.write(content)
            
            elif artifact_type == "hunting_queries":
                with open(cve_dir / f"{cve_id}_hunting_queries_{timestamp}.md", 'w') as f:
                    f.write(content)
            
            elif artifact_type == "response_playbook":
                with open(cve_dir / f"{cve_id}_response_playbook_{timestamp}.yml", 'w') as f:
                    f.write(content)
            
            elif artifact_type == "prototype_rule":
                with open(cve_dir / f"{cve_id}_prototype_rule_{timestamp}.yml", 'w') as f:
                    f.write(content)
            
            elif artifact_type == "community_rule":
                with open(cve_dir / f"{cve_id}_community_rule_{timestamp}.yml", 'w') as f:
                    f.write(content)
        
        self.logger.info(f"Custom artifacts saved for {cve_id}")

    def run_custom_analysis(self, cve_id, description, refs, contributor=None):
        """Run complete custom analysis with all unique differentiators"""
        self.logger.info(f"Starting custom analysis for {cve_id}")
        
        artifacts = {}
        
        # 1. Custom CVE analysis
        custom_analysis = self.generate_custom_cve_analysis(cve_id, description, refs)
        if custom_analysis:
            artifacts["analysis"] = custom_analysis
        
        # 2. Threat hunting queries
        hunting_queries = self.generate_threat_hunting_queries(cve_id, custom_analysis)
        if hunting_queries:
            artifacts["hunting_queries"] = hunting_queries
        
        # 3. Response playbook
        response_playbook = self.create_custom_response_playbook(cve_id, custom_analysis)
        if response_playbook:
            artifacts["response_playbook"] = response_playbook
        
        # 4. Rapid prototype rule
        prototype_rule = self.generate_rapid_prototype_rules(cve_id)
        if prototype_rule:
            artifacts["prototype_rule"] = prototype_rule
        
        # 5. Community rule (if contributor provided)
        if contributor:
            community_rule = self.create_community_rule(cve_id, contributor)
            if community_rule:
                artifacts["community_rule"] = community_rule
        
        # Save all artifacts
        if artifacts:
            self.save_custom_artifacts(cve_id, artifacts)
        
        return artifacts

def main():
    """Main function for testing unique differentiators"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Unique Differentiators for CVE Monitoring")
    parser.add_argument("--cve-id", required=True, help="CVE ID to analyze")
    parser.add_argument("--description", required=True, help="CVE description")
    parser.add_argument("--refs", nargs="+", default=[], help="CVE references")
    parser.add_argument("--contributor", help="Community contributor name")
    
    args = parser.parse_args()
    
    differentiators = UniqueDifferentiators()
    
    # Run custom analysis
    artifacts = differentiators.run_custom_analysis(
        args.cve_id,
        args.description,
        args.refs,
        args.contributor
    )
    
    print(f"\n✅ Custom analysis completed for {args.cve_id}")
    print(f"📁 Generated artifacts: {list(artifacts.keys())}")
    print(f"📂 Check the 'custom_artifacts/{args.cve_id}/' directory for results")

if __name__ == "__main__":
    main() 