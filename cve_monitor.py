#!/usr/bin/env python3
"""
CVE Monitor and Detection Rule Generator
Monitors CVE databases and generates detection rules automatically.
"""

import argparse
import logging
import sys
import requests
import sqlite3
import os
from datetime import datetime, timedelta

def fetch_cves(days_back=1):
    """
    Fetch recent CVEs from the NVD API.
    Returns a list of CVE dictionaries.
    """
    logging.info("Fetching recent CVEs from NVD...")
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    # Correct ISO-8601 format with milliseconds and 'Z' for UTC
    date_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    pub_start = start_date.strftime(date_format)[:-3] + "Z"
    pub_end = end_date.strftime(date_format)[:-3] + "Z"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': pub_start,
        'pubEndDate': pub_end,
        'resultsPerPage': 100
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cves.append({
                'id': cve_data.get('id', ''),
                'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                'published': cve_data.get('published', ''),
                'lastModified': cve_data.get('lastModified', ''),
            })
        logging.info(f"Fetched {len(cves)} CVEs from NVD.")
        return cves
    except Exception as e:
        logging.error(f"Error fetching CVEs from NVD: {e}")
        return []

def init_database():
    """Initialize SQLite database for storing CVEs."""
    db_path = "cve_database.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            description TEXT,
            published TEXT,
            last_modified TEXT,
            processed BOOLEAN DEFAULT FALSE,
            rule_generated BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logging.info("Database initialized successfully.")

def cve_exists(cve_id):
    """Check if a CVE already exists in the database."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM cves WHERE id = ?", (cve_id,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def store_cves(cves):
    """
    Store CVEs in the SQLite database, avoiding duplicates.
    Returns the number of new CVEs stored.
    """
    if not cves:
        logging.info("No CVEs to store.")
        return 0
    
    init_database()
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()
    
    new_cves = 0
    for cve in cves:
        if not cve_exists(cve['id']):
            cursor.execute('''
                INSERT INTO cves (id, description, published, last_modified)
                VALUES (?, ?, ?, ?)
            ''', (cve['id'], cve['description'], cve['published'], cve['lastModified']))
            new_cves += 1
            logging.info(f"Stored new CVE: {cve['id']}")
    
    conn.commit()
    conn.close()
    logging.info(f"Stored {new_cves} new CVEs in the database.")
    return new_cves

def get_unprocessed_cves():
    """Get CVEs that haven't been processed for rule generation."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, description FROM cves WHERE processed = FALSE")
    cves = cursor.fetchall()
    conn.close()
    return [{'id': cve[0], 'description': cve[1]} for cve in cves]

def mark_cve_processed(cve_id):
    """Mark a CVE as processed."""
    conn = sqlite3.connect("cve_database.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE cves SET processed = TRUE WHERE id = ?", (cve_id,))
    conn.commit()
    conn.close()

def generate_detection_rules():
    """
    Generate detection rules for new CVEs for multiple platforms.
    """
    logging.info("Generating detection rules for new CVEs...")
    
    # Get unprocessed CVEs
    unprocessed_cves = get_unprocessed_cves()
    if not unprocessed_cves:
        logging.info("No unprocessed CVEs found.")
        return 0
    
    logging.info(f"Found {len(unprocessed_cves)} unprocessed CVEs.")
    
    # Create output directories for each platform
    platforms = {
        'sigma': 'generated_rules/sigma',
        'crowdstrike': 'generated_rules/crowdstrike', 
        'sentinelone': 'generated_rules/sentinelone',
        'sentinel': 'generated_rules/sentinel'
    }
    
    for platform, directory in platforms.items():
        os.makedirs(directory, exist_ok=True)
    
    rules_generated = 0
    for cve in unprocessed_cves:
        try:
            logging.info(f"Generating rules for {cve['id']}: {cve['description'][:100]}...")
            
            # Generate Sigma rule
            sigma_rule = generate_sigma_rule(cve)
            sigma_filename = f"{platforms['sigma']}/{cve['id']}_detection.yml"
            with open(sigma_filename, 'w') as f:
                f.write(sigma_rule)
            
            # Generate CrowdStrike rule
            crowdstrike_rule = generate_crowdstrike_rule(cve)
            crowdstrike_filename = f"{platforms['crowdstrike']}/{cve['id']}_detection.falcon"
            with open(crowdstrike_filename, 'w') as f:
                f.write(crowdstrike_rule)
            
            # Generate SentinelOne rule
            sentinelone_rule = generate_sentinelone_rule(cve)
            sentinelone_filename = f"{platforms['sentinelone']}/{cve['id']}_detection.sql"
            with open(sentinelone_filename, 'w') as f:
                f.write(sentinelone_rule)
            
            # Generate Sentinel rule
            sentinel_rule = generate_sentinel_rule(cve)
            sentinel_filename = f"{platforms['sentinel']}/{cve['id']}_detection.kql"
            with open(sentinel_filename, 'w') as f:
                f.write(sentinel_rule)
            
            # Mark as processed
            mark_cve_processed(cve['id'])
            rules_generated += 1
            logging.info(f"Generated rules for {cve['id']}: Sigma, CrowdStrike, SentinelOne, Sentinel")
            
        except Exception as e:
            logging.error(f"Error generating rules for {cve['id']}: {e}")
    
    logging.info(f"Generated {rules_generated} detection rule sets (4 platforms each).")
    return rules_generated

def generate_sigma_rule(cve):
    """Generate a Sigma detection rule."""
    return f"""title: Detection for {cve['id']}
description: Generated detection rule for {cve['id']}
author: CVE Monitor
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious_activity'
    condition: selection
level: medium
tags:
    - attack.initial_access
    - cve.{cve['id']}
"""

def generate_crowdstrike_rule(cve):
    """Generate a CrowdStrike Falcon detection rule."""
    description_escaped = cve['description'].replace('"', '\\"')
    return f"""# CrowdStrike Falcon Detection Rule for {cve['id']}
# Generated by CVE Monitor
# Date: {datetime.now().strftime('%Y-%m-%d')}

event_simpleName=ProcessRollup2
| eval cve_id="{cve['id']}"
| eval description="{description_escaped}"
| where CommandLine="*suspicious_activity*"
| table ComputerName, UserName, CommandLine, cve_id, description
"""

def generate_sentinelone_rule(cve):
    """Generate a SentinelOne detection rule."""
    description_escaped = cve['description'].replace("'", "''")
    return f"""-- SentinelOne Detection Rule for {cve['id']}
-- Generated by CVE Monitor
-- Date: {datetime.now().strftime('%Y-%m-%d')}

SELECT 
    agent_id,
    agent_name,
    process_name,
    process_command_line,
    process_username,
    '{cve['id']}' as cve_id,
    '{description_escaped}' as description
FROM events 
WHERE event_type = 'process'
AND process_command_line LIKE '%suspicious_activity%'
"""

def generate_sentinel_rule(cve):
    """Generate an Azure Sentinel detection rule."""
    description_escaped = cve['description'].replace('"', '\\"')
    return f"""// Azure Sentinel Detection Rule for {cve['id']}
// Generated by CVE Monitor
// Date: {datetime.now().strftime('%Y-%m-%d')}

SecurityEvent
| where EventID == 4688
| where CommandLine contains "suspicious_activity"
| extend CVE_ID = "{cve['id']}"
| extend Description = "{description_escaped}"
| project TimeGenerated, Computer, SubjectUserName, CommandLine, CVE_ID, Description
"""

def show_stats():
    """
    Show monitoring statistics from the database.
    """
    logging.info("Showing monitoring statistics...")
    
    try:
        conn = sqlite3.connect("cve_database.db")
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]
        
        # Processed CVEs
        cursor.execute("SELECT COUNT(*) FROM cves WHERE processed = TRUE")
        processed_cves = cursor.fetchone()[0]
        
        # Rules generated
        cursor.execute("SELECT COUNT(*) FROM cves WHERE rule_generated = TRUE")
        rules_generated = cursor.fetchone()[0]
        
        # Recent CVEs (last 7 days)
        cursor.execute("""
            SELECT COUNT(*) FROM cves 
            WHERE created_at >= datetime('now', '-7 days')
        """)
        recent_cves = cursor.fetchone()[0]
        
        # Latest CVEs
        cursor.execute("""
            SELECT id, description, created_at 
            FROM cves 
            ORDER BY created_at DESC 
            LIMIT 5
        """)
        latest_cves = cursor.fetchall()
        
        conn.close()
        
        print("\n=== CVE Monitoring Statistics ===")
        print(f"Total CVEs in database: {total_cves}")
        print(f"Processed CVEs: {processed_cves}")
        print(f"Rules generated: {rules_generated}")
        print(f"Recent CVEs (7 days): {recent_cves}")
        
        if latest_cves:
            print("\nLatest CVEs:")
            for cve in latest_cves:
                print(f"  {cve[0]} - {cve[1][:80]}... ({cve[2]})")
        
        print("\n" + "="*40)
        
    except Exception as e:
        logging.error(f"Error showing statistics: {e}")
        print("Error: Could not retrieve statistics from database.")

def main():
    parser = argparse.ArgumentParser(description="CVE Monitor and Detection Rule Generator")
    parser.add_argument('--monitor', action='store_true', help='Run CVE monitoring')
    parser.add_argument('--generate-rules', action='store_true', help='Generate detection rules')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (continuous monitoring)')
    parser.add_argument('--interval', type=int, default=24, help='Monitoring interval in hours (daemon mode)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    # Always initialize the database and tables first
    init_database()

    if args.stats:
        show_stats()
    elif args.generate_rules:
        generate_detection_rules()
    elif args.daemon:
        logging.info(f"Starting daemon mode (interval: {args.interval} hours)")
        try:
            while True:
                cves = fetch_cves()
                store_cves(cves)
                generate_detection_rules()
                logging.info(f"Sleeping for {args.interval} hours...")
                import time
                time.sleep(args.interval * 3600)
        except KeyboardInterrupt:
            logging.info("Daemon stopped by user.")
            sys.exit(0)
    elif args.monitor:
        cves = fetch_cves()
        store_cves(cves)
        generate_detection_rules()
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 