#!/usr/bin/env python3
"""
Enhanced CVE Monitoring and Detection Rule Generation System
Integrates with unique differentiators for organization-specific analysis
"""

import argparse
import logging
import sys
import requests
import sqlite3
import os
from datetime import datetime, timedelta
import json
import time
import openai

# Import unique differentiators
try:
    from unique_differentiators import UniqueDifferentiators
    UNIQUE_DIFF_AVAILABLE = True
except ImportError:
    UNIQUE_DIFF_AVAILABLE = False
    print("⚠️  Unique differentiators module not available. Install with: pip install openai")

class CVEMonitor:
    def __init__(self, db_path="cve_database.db"):
        self.db_path = db_path
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        self.github_token = os.environ.get('GITHUB_TOKEN')
        self.setup_logging()
        self.setup_database()
        
        # Initialize unique differentiators if available
        self.unique_diff = None
        if UNIQUE_DIFF_AVAILABLE and self.openai_api_key:
            try:
                self.unique_diff = UniqueDifferentiators()
                self.logger.info("✅ Unique differentiators initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize unique differentiators: {e}")

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(message)s',
            handlers=[
                logging.FileHandler('cve_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                refs TEXT,
                processed BOOLEAN DEFAULT FALSE,
                sigma_rule_generated BOOLEAN DEFAULT FALSE,
                custom_analysis_generated BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        self.logger.info("Database initialized")

    def fetch_nvd_cves(self, days_back=7):
        """Fetch CVEs from NVD API"""
        if not self.openai_api_key:
            self.logger.error("OpenAI API key not set")
            return []
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        # Format dates for NVD API (ISO-8601 with milliseconds and Z)
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "resultsPerPage": 2000
        }
        
        try:
            self.logger.info(f"Fetching CVEs from {start_str} to {end_str}")
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = data.get('vulnerabilities', [])
            
            self.logger.info(f"Fetched {len(cves)} CVEs from NVD")
            return cves
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching from NVD: {e}")
            return []

    def fetch_github_cves(self, days_back=7):
        """Fetch CVEs from GitHub Security Advisories"""
        if not self.github_token:
            self.logger.warning("GitHub token not set, skipping GitHub CVEs")
            return []
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        # GitHub GraphQL query for security advisories
        query = """
        query($cursor: String) {
          securityVulnerabilities(first: 100, after: $cursor) {
            nodes {
              advisory {
                id
                summary
                severity
                publishedAt
                updatedAt
                references {
                  url
                }
              }
              vulnerableRequirements
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
        """
        
        cves = []
        cursor = None
        
        try:
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Content-Type": "application/json"
            }
            
            while True:
                variables = {"cursor": cursor} if cursor else {}
                
                response = requests.post(
                    "https://api.github.com/graphql",
                    json={"query": query, "variables": variables},
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data['data']['securityVulnerabilities']['nodes']
                
                for vuln in vulnerabilities:
                    advisory = vuln['advisory']
                    published_at = datetime.fromisoformat(advisory['publishedAt'].replace('Z', '+00:00'))
                    
                    if start_date <= published_at <= end_date:
                        cve_data = {
                            'cve': {
                                'id': advisory['id'],
                                'descriptions': [{'value': advisory['summary']}],
                                'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': advisory['severity']}}]},
                                'references': [{'url': ref['url']} for ref in advisory['references']],
                                'published': advisory['publishedAt'],
                                'lastModified': advisory['updatedAt']
                            }
                        }
                        cves.append(cve_data)
                
                page_info = data['data']['securityVulnerabilities']['pageInfo']
                if not page_info['hasNextPage']:
                    break
                cursor = page_info['endCursor']
                
                # Rate limiting
                time.sleep(1)
            
            self.logger.info(f"Fetched {len(cves)} CVEs from GitHub")
            return cves
            
        except Exception as e:
            self.logger.error(f"Error fetching from GitHub: {e}")
            return []

    def store_cves(self, cves):
        """Store CVEs in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stored_count = 0
        for cve_data in cves:
            try:
                cve = cve_data['cve']
                cve_id = cve['id']
                
                # Check if CVE already exists
                cursor.execute("SELECT id FROM cves WHERE id = ?", (cve_id,))
                if cursor.fetchone():
                    continue
                
                # Extract description
                descriptions = cve.get('descriptions', [])
                description = descriptions[0]['value'] if descriptions else "No description available"
                
                # Extract severity
                metrics = cve.get('metrics', {})
                cvss_metrics = metrics.get('cvssMetricV31', [])
                severity = cvss_metrics[0]['cvssData']['baseSeverity'] if cvss_metrics else "UNKNOWN"
                
                # Extract references
                references = cve.get('references', [])
                ref_urls = [ref['url'] for ref in references]
                
                cursor.execute('''
                    INSERT INTO cves (id, description, severity, published_date, last_modified_date, refs)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    description,
                    severity,
                    cve.get('published'),
                    cve.get('lastModified'),
                    json.dumps(ref_urls)
                ))
                
                stored_count += 1
                
            except Exception as e:
                self.logger.error(f"Error storing CVE {cve.get('id', 'unknown')}: {e}")
        
        conn.commit()
        conn.close()
        self.logger.info(f"Stored {stored_count} new CVEs in database")

    def generate_detection_rules(self, cve_id=None, limit=10):
        """Generate detection rules for CVEs"""
        if not self.openai_api_key:
            self.logger.error("OpenAI API key not set")
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if cve_id:
            cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
            cves = cursor.fetchall()
        else:
            cursor.execute("SELECT * FROM cves WHERE sigma_rule_generated = FALSE ORDER BY created_at DESC LIMIT ?", (limit,))
            cves = cursor.fetchall()
        
        conn.close()
        
        if not cves:
            self.logger.info("No CVEs to process")
            return
        
        self.logger.info(f"Generating detection rules for {len(cves)} CVEs")
        
        for cve in cves:
            try:
                self.generate_single_cve_rules(cve)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                self.logger.error(f"Error generating rules for {cve[0]}: {e}")

    def generate_single_cve_rules(self, cve):
        """Generate rules for a single CVE"""
        cve_id, description, severity, published_date, last_modified_date, refs_json, processed, sigma_generated, custom_analysis_generated, created_at = cve
        
        if not self.openai_api_key:
            return
        
        try:
            client = openai.OpenAI(api_key=self.openai_api_key)
            
            # Parse references
            references = json.loads(refs_json) if refs_json else []
            
            # Enhanced prompt with more context
            prompt = f"""
            Generate comprehensive detection rules for CVE {cve_id}.
            
            CVE Details:
            - ID: {cve_id}
            - Description: {description}
            - Severity: {severity}
            - Published: {published_date}
            - References: {', '.join(references)}
            
            Generate detection rules in the following formats:
            1. Sigma rule (YAML format)
            2. CrowdStrike Falcon query
            3. SentinelOne query (SQL)
            4. Azure Sentinel query (KQL)
            
            For each platform, provide:
            - Detection logic based on the CVE description
            - Relevant event types and fields
            - Appropriate thresholds and conditions
            - Tags and metadata
            
            Make the rules practical and actionable for security teams.
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=3000
            )
            
            rules_content = response.choices[0].message.content
            
            # Parse and save rules for different platforms
            self.save_platform_rules(cve_id, rules_content, severity)
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE cves SET sigma_rule_generated = TRUE WHERE id = ?", (cve_id,))
            conn.commit()
            conn.close()
            
            self.logger.info(f"Generated detection rules for {cve_id}")
            
            # Generate custom analysis if unique differentiators are available
            if self.unique_diff:
                try:
                    self.logger.info(f"Generating custom analysis for {cve_id}")
                    custom_artifacts = self.unique_diff.run_custom_analysis(
                        cve_id, 
                        description, 
                        references
                    )
                    
                    if custom_artifacts:
                        # Update database
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        cursor.execute("UPDATE cves SET custom_analysis_generated = TRUE WHERE id = ?", (cve_id,))
                        conn.commit()
                        conn.close()
                        
                        self.logger.info(f"Generated custom analysis artifacts for {cve_id}")
                        
                except Exception as e:
                    self.logger.error(f"Error generating custom analysis for {cve_id}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error generating rules for {cve_id}: {e}")

    def save_platform_rules(self, cve_id, rules_content, severity):
        """Save rules for different platforms"""
        # Create directories if they don't exist
        platforms = {
            'sigma': 'generated_rules/sigma',
            'crowdstrike': 'generated_rules/crowdstrike',
            'sentinelone': 'generated_rules/sentinelone',
            'sentinel': 'generated_rules/sentinel'
        }
        
        for platform, directory in platforms.items():
            os.makedirs(directory, exist_ok=True)
        
        # Extract and save Sigma rule
        try:
            sigma_rule = self.extract_sigma_rule(rules_content)
            if sigma_rule:
                sigma_file = f"generated_rules/sigma/{cve_id}_detection.yml"
                with open(sigma_file, 'w') as f:
                    f.write(sigma_rule)
                self.logger.info(f"Saved Sigma rule: {sigma_file}")
        except Exception as e:
            self.logger.error(f"Error saving Sigma rule for {cve_id}: {e}")
        
        # Extract and save CrowdStrike rule
        try:
            crowdstrike_rule = self.extract_crowdstrike_rule(rules_content)
            if crowdstrike_rule:
                crowdstrike_file = f"generated_rules/crowdstrike/{cve_id}_detection.falcon"
                with open(crowdstrike_file, 'w') as f:
                    f.write(crowdstrike_rule)
                self.logger.info(f"Saved CrowdStrike rule: {crowdstrike_file}")
        except Exception as e:
            self.logger.error(f"Error saving CrowdStrike rule for {cve_id}: {e}")
        
        # Extract and save SentinelOne rule
        try:
            sentinelone_rule = self.extract_sentinelone_rule(rules_content)
            if sentinelone_rule:
                sentinelone_file = f"generated_rules/sentinelone/{cve_id}_detection.sql"
                with open(sentinelone_file, 'w') as f:
                    f.write(sentinelone_rule)
                self.logger.info(f"Saved SentinelOne rule: {sentinelone_file}")
        except Exception as e:
            self.logger.error(f"Error saving SentinelOne rule for {cve_id}: {e}")
        
        # Extract and save Sentinel rule
        try:
            sentinel_rule = self.extract_sentinel_rule(rules_content)
            if sentinel_rule:
                sentinel_file = f"generated_rules/sentinel/{cve_id}_detection.kql"
                with open(sentinel_file, 'w') as f:
                    f.write(sentinel_rule)
                self.logger.info(f"Saved Sentinel rule: {sentinel_file}")
        except Exception as e:
            self.logger.error(f"Error saving Sentinel rule for {cve_id}: {e}")

    def extract_sigma_rule(self, content):
        """Extract Sigma rule from AI response"""
        # Look for YAML content between markdown code blocks
        import re
        yaml_pattern = r'```yaml\s*\n(.*?)\n```'
        match = re.search(yaml_pattern, content, re.DOTALL)
        if match:
            return match.group(1)
        
        # Fallback: look for YAML-like content
        lines = content.split('\n')
        yaml_lines = []
        in_yaml = False
        
        for line in lines:
            if 'title:' in line or 'id:' in line:
                in_yaml = True
            if in_yaml:
                yaml_lines.append(line)
            if in_yaml and line.strip() == '':
                break
        
        return '\n'.join(yaml_lines) if yaml_lines else None

    def extract_crowdstrike_rule(self, content):
        """Extract CrowdStrike rule from AI response"""
        # Look for CrowdStrike-specific content
        lines = content.split('\n')
        falcon_lines = []
        in_falcon = False
        
        for line in lines:
            if 'crowdstrike' in line.lower() or 'falcon' in line.lower():
                in_falcon = True
            if in_falcon:
                falcon_lines.append(line)
            if in_falcon and line.strip() == '':
                break
        
        return '\n'.join(falcon_lines) if falcon_lines else None

    def extract_sentinelone_rule(self, content):
        """Extract SentinelOne rule from AI response"""
        # Look for SQL content
        import re
        sql_pattern = r'```sql\s*\n(.*?)\n```'
        match = re.search(sql_pattern, content, re.DOTALL)
        if match:
            return match.group(1)
        
        # Fallback: look for SQL-like content
        lines = content.split('\n')
        sql_lines = []
        in_sql = False
        
        for line in lines:
            if 'SELECT' in line.upper() or 'FROM' in line.upper():
                in_sql = True
            if in_sql:
                sql_lines.append(line)
            if in_sql and line.strip() == '':
                break
        
        return '\n'.join(sql_lines) if sql_lines else None

    def extract_sentinel_rule(self, content):
        """Extract Sentinel rule from AI response"""
        # Look for KQL content
        import re
        kql_pattern = r'```kql\s*\n(.*?)\n```'
        match = re.search(kql_pattern, content, re.DOTALL)
        if match:
            return match.group(1)
        
        # Fallback: look for KQL-like content
        lines = content.split('\n')
        kql_lines = []
        in_kql = False
        
        for line in lines:
            if 'SecurityEvent' in line or 'Sysmon' in line or 'EventLog' in line:
                in_kql = True
            if in_kql:
                kql_lines.append(line)
            if in_kql and line.strip() == '':
                break
        
        return '\n'.join(kql_lines) if kql_lines else None

    def get_statistics(self):
        """Get CVE processing statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]
        
        # CVEs by severity
        cursor.execute("SELECT severity, COUNT(*) FROM cves GROUP BY severity")
        severity_stats = dict(cursor.fetchall())
        
        # Processing status
        cursor.execute("SELECT COUNT(*) FROM cves WHERE sigma_rule_generated = TRUE")
        rules_generated = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cves WHERE custom_analysis_generated = TRUE")
        custom_analysis_generated = cursor.fetchone()[0]
        
        # Recent CVEs
        cursor.execute("SELECT COUNT(*) FROM cves WHERE created_at >= datetime('now', '-7 days')")
        recent_cves = cursor.fetchone()[0]
        
        conn.close()
        
        stats = {
            'total_cves': total_cves,
            'severity_distribution': severity_stats,
            'rules_generated': rules_generated,
            'custom_analysis_generated': custom_analysis_generated,
            'recent_cves': recent_cves,
            'unique_differentiators_available': UNIQUE_DIFF_AVAILABLE
        }
        
        return stats

    def run_monitoring(self, days_back=7):
        """Run complete monitoring process"""
        self.logger.info("Starting CVE monitoring process")
        
        # Fetch CVEs from multiple sources
        nvd_cves = self.fetch_nvd_cves(days_back)
        github_cves = self.fetch_github_cves(days_back)
        
        # Combine and store CVEs
        all_cves = nvd_cves + github_cves
        self.store_cves(all_cves)
        
        # Generate detection rules
        self.generate_detection_rules()
        
        # Show statistics
        stats = self.get_statistics()
        self.logger.info("Monitoring process completed")
        self.logger.info(f"Statistics: {stats}")

    def run_daemon(self, interval_hours=24):
        """Run as a daemon process"""
        self.logger.info(f"Starting CVE monitoring daemon (interval: {interval_hours} hours)")
        
        while True:
            try:
                self.run_monitoring()
                self.logger.info(f"Daemon cycle completed. Sleeping for {interval_hours} hours...")
                time.sleep(interval_hours * 3600)
            except KeyboardInterrupt:
                self.logger.info("Daemon stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Daemon error: {e}")
                time.sleep(3600)  # Wait 1 hour before retrying

def main():
    parser = argparse.ArgumentParser(description="CVE Monitoring and Detection Rule Generation")
    parser.add_argument('--mode', choices=['monitor', 'generate', 'stats', 'daemon', 'full'], 
                       default='full', help='Operation mode')
    parser.add_argument('--days', type=int, default=7, help='Days back to fetch CVEs')
    parser.add_argument('--cve-id', help='Specific CVE ID to process')
    parser.add_argument('--limit', type=int, default=10, help='Limit number of CVEs to process')
    parser.add_argument('--interval', type=int, default=24, help='Daemon interval in hours')
    
    args = parser.parse_args()
    
    monitor = CVEMonitor()
    
    if args.mode == 'monitor':
        monitor.run_monitoring(args.days)
    elif args.mode == 'generate':
        if args.cve_id:
            monitor.generate_detection_rules(cve_id=args.cve_id)
        else:
            monitor.generate_detection_rules(limit=args.limit)
    elif args.mode == 'stats':
        stats = monitor.get_statistics()
        print(json.dumps(stats, indent=2))
    elif args.mode == 'daemon':
        monitor.run_daemon(args.interval)
    elif args.mode == 'full':
        # Run complete process: monitor + generate + stats
        monitor.run_monitoring(args.days)
        monitor.generate_detection_rules(limit=args.limit)
        stats = monitor.get_statistics()
        print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main() 