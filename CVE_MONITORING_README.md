# CVE Monitoring & Rule Generation System

This repository now includes a comprehensive CVE monitoring and detection rule generation system that automatically fetches CVEs from multiple sources and generates detection rules for multiple security platforms.

## 🚀 Features

- **Multi-Source CVE Monitoring**: Fetches CVEs from NVD API and GitHub Security Advisories
- **Multi-Platform Rule Generation**: Creates detection rules for:
  - Sigma (YAML format)
  - CrowdStrike Falcon (SPL format)
  - Azure Sentinel (KQL format)
  - SentinelOne (SQL format)
- **AI-Powered Generation**: Uses OpenAI API for intelligent rule creation
- **Database Tracking**: SQLite database for CVE tracking and management
- **Automated Workflows**: GitHub Actions integration for continuous monitoring
- **Command-Line Interface**: Flexible CLI for manual operations

## 📁 System Components

### Core Files
- `cve_monitor.py` - Main CVE monitoring and rule generation tool
- `cve_database.db` - SQLite database for CVE tracking
- `generated_rules/` - Directory containing all generated detection rules

### Workflows
- `.github/workflows/sigma_auto.yml` - Enhanced workflow with both single CVE and monitoring modes
- `.github/workflows/cve-monitor.yml` - Dedicated CVE monitoring workflow

## 🔧 Setup

### Prerequisites
- Python 3.11+
- OpenAI API key
- GitHub token with appropriate permissions

### Environment Variables
Set these in your GitHub repository secrets:
- `OPENAI_API_KEY` - Your OpenAI API key
- `CUSTOM_GITHUB_TOKEN` - GitHub token with repo permissions

### Local Installation
```bash
pip install pyyaml requests openai sqlite3
```

## 🎯 Usage

### Command Line Interface

#### Monitor CVEs
```bash
# Monitor CVEs from the last 7 days
python cve_monitor.py --monitor --days 7

# Monitor CVEs from the last 1 day (default)
python cve_monitor.py --monitor --days 1
```

#### Generate Detection Rules
```bash
# Generate rules for all platforms
python cve_monitor.py --generate --platform all

# Generate rules for specific platform
python cve_monitor.py --generate --platform sigma
python cve_monitor.py --generate --platform crowdstrike
python cve_monitor.py --generate --platform sentinel
python cve_monitor.py --generate --platform sentinelone
```

#### View Statistics
```bash
python cve_monitor.py --stats
```

#### Run in Daemon Mode
```bash
python cve_monitor.py --daemon --interval 3600
```

### GitHub Actions Workflows

#### 1. Enhanced Sigma Auto Workflow (`.github/workflows/sigma_auto.yml`)

**Manual Trigger Options:**
- **Single CVE Mode**: Generate rules for a specific CVE ID
- **Monitor Mode**: Run CVE monitoring for specified days
- **Generate Mode**: Generate rules for all platforms
- **Stats Mode**: View CVE monitoring statistics

**Automatic Triggers:**
- Daily monitoring at 6 AM UTC

#### 2. Dedicated CVE Monitor Workflow (`.github/workflows/cve-monitor.yml`)

**Manual Trigger Options:**
- **Monitor**: Monitor CVEs for specified days
- **Generate**: Generate rules for specified platform(s)
- **Stats**: View monitoring statistics
- **Daemon**: Run continuous monitoring

**Automatic Triggers:**
- Daily monitoring at 6 AM UTC
- Weekly monitoring on Sundays at 8 AM UTC

## 📊 Generated Rules Structure

```
generated_rules/
├── sigma/
│   ├── CVE-2023-28902_detection.yml
│   ├── CVE-2023-28903_detection.yml
│   └── ...
├── crowdstrike/
│   ├── CVE-2023-28902_detection.falcon
│   ├── CVE-2023-28903_detection.falcon
│   └── ...
├── sentinel/
│   ├── CVE-2023-28902_detection.kql
│   ├── CVE-2023-28903_detection.kql
│   └── ...
└── sentinelone/
    ├── CVE-2023-28902_detection.sql
    ├── CVE-2023-28903_detection.sql
    └── ...
```

## 🔄 Workflow Integration

### Existing SigmaAgent Integration
The system maintains compatibility with your existing `SigmaAgent.py` for single CVE processing while adding comprehensive monitoring capabilities.

### Automated Operations
1. **Daily Monitoring**: Automatically fetches new CVEs and generates rules
2. **Weekly Monitoring**: Comprehensive monitoring with extended time range
3. **Manual Triggers**: On-demand monitoring and rule generation
4. **Artifact Storage**: Workflow artifacts for database and generated rules

## 📈 Monitoring Capabilities

### CVE Sources
- **NVD API**: National Vulnerability Database
- **GitHub Security Advisories**: GitHub's security advisory database

### Data Tracking
- CVE ID, description, severity, and references
- Publication and modification dates
- Rule generation status and timestamps
- Platform-specific rule counts

### Statistics
- Total CVEs monitored
- Rules generated per platform
- Success/failure rates
- Database health metrics

## 🛠️ Configuration

### Database Management
The SQLite database (`cve_database.db`) automatically tracks:
- CVE metadata and descriptions
- Rule generation status
- Timestamps for monitoring and generation
- Platform-specific rule information

### API Rate Limiting
The system includes built-in rate limiting for:
- NVD API calls (5 requests per 30 seconds)
- GitHub API calls (5000 requests per hour)
- OpenAI API calls (with retry logic)

## 🔍 Troubleshooting

### Common Issues
1. **API Rate Limits**: System automatically handles rate limiting
2. **Database Locking**: Ensure only one instance runs at a time
3. **Token Permissions**: Verify GitHub token has appropriate repo permissions
4. **OpenAI API Errors**: Check API key validity and quota

### Debug Mode
```bash
python cve_monitor.py --monitor --days 1 --verbose
```

## 📝 Contributing

When contributing to the CVE monitoring system:
1. Test changes locally before pushing
2. Update documentation for new features
3. Ensure backward compatibility with existing workflows
4. Follow the existing code style and patterns

## 🔗 Related Files

- `secrets/SigmaAgent.py` - Original single CVE processing agent
- `secrets/sigma_config.json` - Configuration for SigmaAgent
- `.github/workflows/` - All GitHub Actions workflows

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review workflow logs in GitHub Actions
3. Examine the database for data integrity
4. Verify API credentials and permissions

---

**Note**: This system is designed to work alongside your existing Sigma rule automation while providing comprehensive CVE monitoring capabilities. 