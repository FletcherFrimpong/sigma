#!/usr/bin/env python3
"""
Setup script for unique differentiators
Helps configure the system for your specific organization
"""

import json
import os
from pathlib import Path

def setup_organization_config():
    """Interactive setup for organization configuration"""
    print("🔧 Setting up organization configuration...")
    print("This will customize the CVE analysis for your specific environment.\n")
    
    config = {
        "organization": {},
        "threat_landscape": {},
        "custom_controls": {}
    }
    
    # Organization details
    print("📋 Organization Information:")
    config["organization"]["name"] = input("Organization name: ").strip() or "Your Organization"
    config["organization"]["industry"] = input("Industry (technology/healthcare/financial/government/etc.): ").strip() or "technology"
    config["organization"]["size"] = input("Organization size (small/medium/large): ").strip() or "medium"
    config["organization"]["risk_tolerance"] = input("Risk tolerance (low/medium/high): ").strip() or "medium"
    
    # Compliance requirements
    print("\n📋 Compliance Requirements (comma-separated):")
    compliance_input = input("e.g., SOX,PCI-DSS,HIPAA,GDPR: ").strip()
    config["organization"]["compliance_requirements"] = [c.strip() for c in compliance_input.split(",")] if compliance_input else ["SOX", "PCI-DSS"]
    
    # Geographic regions
    print("\n🌍 Geographic Regions (comma-separated):")
    regions_input = input("e.g., US,EU,APAC: ").strip()
    config["organization"]["geographic_regions"] = [r.strip() for r in regions_input.split(",")] if regions_input else ["US", "EU"]
    
    # Technology stack
    print("\n💻 Technology Stack (comma-separated):")
    tech_input = input("e.g., AWS,Azure,Linux,Windows,Docker,Kubernetes: ").strip()
    config["organization"]["technology_stack"] = [t.strip() for t in tech_input.split(",")] if tech_input else ["AWS", "Azure", "Linux", "Windows"]
    
    # Security tools
    print("\n🛡️ Security Tools (comma-separated):")
    tools_input = input("e.g., CrowdStrike,SIEM,Firewall,EDR: ").strip()
    config["organization"]["security_tools"] = [tool.strip() for tool in tools_input.split(",")] if tools_input else ["CrowdStrike", "SIEM", "Firewall"]
    
    # Threat landscape
    print("\n🎯 Threat Landscape:")
    print("Primary threats (comma-separated):")
    threats_input = input("e.g., ransomware,phishing,insider_threats: ").strip()
    config["threat_landscape"]["primary_threats"] = [t.strip() for t in threats_input.split(",")] if threats_input else ["ransomware", "phishing", "insider_threats"]
    
    print("Targeted assets (comma-separated):")
    assets_input = input("e.g., customer_data,intellectual_property,financial_systems: ").strip()
    config["threat_landscape"]["targeted_assets"] = [a.strip() for a in assets_input.split(",")] if assets_input else ["customer_data", "intellectual_property", "financial_systems"]
    
    print("Known threat actors (comma-separated):")
    actors_input = input("e.g., APT29,Lazarus Group: ").strip()
    config["threat_landscape"]["known_threat_actors"] = [a.strip() for a in actors_input.split(",")] if actors_input else ["APT29", "Lazarus Group"]
    
    print("Attack vectors (comma-separated):")
    vectors_input = input("e.g., email,web,supply_chain: ").strip()
    config["threat_landscape"]["attack_vectors"] = [v.strip() for v in vectors_input.split(",")] if vectors_input else ["email", "web", "supply_chain"]
    
    # Custom controls
    print("\n🔧 Custom Controls:")
    print("Existing detections (comma-separated):")
    detections_input = input("e.g., EDR,SIEM,Firewall: ").strip()
    config["custom_controls"]["existing_detections"] = [d.strip() for d in detections_input.split(",")] if detections_input else ["EDR", "SIEM", "Firewall"]
    
    print("Response capabilities (comma-separated):")
    capabilities_input = input("e.g., automated_isolation,manual_investigation: ").strip()
    config["custom_controls"]["response_capabilities"] = [c.strip() for c in capabilities_input.split(",")] if capabilities_input else ["automated_isolation", "manual_investigation"]
    
    print("Notification channels (comma-separated):")
    notifications_input = input("e.g., email,slack,teams: ").strip()
    config["custom_controls"]["notification_channels"] = [n.strip() for n in notifications_input.split(",")] if notifications_input else ["email", "slack", "teams"]
    
    # Save configuration
    with open("org_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Organization configuration saved to org_config.json")
    return config

def setup_custom_prompts():
    """Setup custom AI prompts"""
    print("\n🤖 Setting up custom AI prompts...")
    print("These prompts will be used to generate organization-specific analysis.\n")
    
    prompts = {
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
    
    # Save prompts
    with open("custom_prompts.json", "w") as f:
        json.dump(prompts, f, indent=2)
    
    print("✅ Custom prompts saved to custom_prompts.json")
    return prompts

def setup_integrations():
    """Setup integration configurations"""
    print("\n🔗 Setting up integrations...")
    print("Configure integrations with your security tools.\n")
    
    integrations = {
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
    
    # Customize Slack channels
    print("Slack notification channels (comma-separated):")
    slack_channels_input = input("e.g., #security-alerts,#incident-response: ").strip()
    if slack_channels_input:
        integrations["slack"]["channels"] = [c.strip() for c in slack_channels_input.split(",")]
    
    # Customize email recipients
    print("Email notification recipients (comma-separated):")
    email_recipients_input = input("e.g., security@company.com,it@company.com: ").strip()
    if email_recipients_input:
        integrations["email"]["recipients"] = [r.strip() for r in email_recipients_input.split(",")]
    
    # Save integrations
    with open("integrations.json", "w") as f:
        json.dump(integrations, f, indent=2)
    
    print("✅ Integrations saved to integrations.json")
    return integrations

def create_directories():
    """Create necessary directories"""
    directories = [
        "custom_artifacts",
        "custom_artifacts/analysis",
        "custom_artifacts/hunting",
        "custom_artifacts/playbooks",
        "custom_artifacts/prototypes",
        "custom_artifacts/community"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Created custom artifacts directories")

def main():
    """Main setup function"""
    print("🚀 Setting up Unique Differentiators for CVE Monitoring")
    print("=" * 60)
    
    # Check if OpenAI API key is set
    if not os.environ.get('OPENAI_API_KEY'):
        print("⚠️  Warning: OPENAI_API_KEY environment variable not set")
        print("   Set it with: export OPENAI_API_KEY='your-api-key'")
        print("   Or add it to your GitHub Secrets for automated workflows\n")
    
    # Run setup functions
    try:
        setup_organization_config()
        setup_custom_prompts()
        setup_integrations()
        create_directories()
        
        print("\n🎉 Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Customize the generated configuration files as needed")
        print("2. Test the system with: python unique_differentiators.py --cve-id CVE-2024-1234 --description 'Test CVE'")
        print("3. Integrate with your existing CVE monitoring workflow")
        print("4. Share community rules and contribute to the threat intelligence")
        
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted by user")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")

if __name__ == "__main__":
    main() 