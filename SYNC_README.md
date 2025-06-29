# Sigma Repository Synchronization Guide

This guide explains how to keep your local repository in sync with the remote GitHub repository when using the automated Sigma rule generation workflow.

## Overview

When you run the GitHub Actions workflow (`sigma_auto.yml`), it:
1. Creates new branches for each CVE
2. Generates detection rules for multiple platforms
3. Commits the rules to the new branches
4. Creates pull requests automatically

Your local repository needs to be synchronized to see these changes.

## Quick Sync

### Basic Sync Script
Run the basic sync script to quickly update your local repository:

```bash
./sync_local.sh
```

This will:
- Fetch all remote changes
- Update your current branch
- Show recent commits and branches
- Clean up merged branches

### Advanced Sync Script
For more detailed information and branch management:

```bash
./advanced_sync.sh
```

This provides:
- Colored output for better readability
- Detailed branch information
- Recent activity overview
- Auto-branch management
- PR information
- Option to switch to specific branches

## Manual Sync Commands

If you prefer to sync manually, use these commands:

### 1. Fetch all remote changes
```bash
git fetch --all --prune
```

### 2. Update your current branch
```bash
git pull origin $(git branch --show-current)
```

### 3. List all branches (local and remote)
```bash
git branch -a
```

### 4. Switch to a specific auto-generated branch
```bash
git checkout -b auto/multi_platform_abc123 origin/auto/multi_platform_abc123
```

### 5. View recent commits
```bash
git log --oneline -10
```

## Workflow Process

### 1. Run the GitHub Actions Workflow
1. Go to your GitHub repository
2. Navigate to Actions → Sigma Rule Automation
3. Click "Run workflow"
4. Enter a CVE ID (e.g., `CVE-2025-49144`)
5. Click "Run workflow"

### 2. Monitor the Workflow
- Watch the workflow progress in the Actions tab
- Check the logs for any errors
- Note the branch name that gets created

### 3. Sync Your Local Repository
After the workflow completes:

```bash
# Basic sync
./sync_local.sh

# Or advanced sync
./advanced_sync.sh
```

### 4. Review Generated Rules
The rules will be in the following directories:
- **Sigma rules**: `rules/` (main directory)
- **Azure Sentinel**: `rules/sentinel/`
- **CrowdStrike**: `rules/crowdstrike/`
- **SentinelOne**: `rules/sentinelone/`

### 5. Review and Merge PRs
1. Go to the Pull Requests tab on GitHub
2. Review the auto-generated PR
3. Check the generated rules
4. Merge when satisfied

## Branch Management

### Auto-Generated Branches
The workflow creates branches with the pattern: `auto/multi_platform_<hash>`

### Cleaning Up Branches
After merging PRs, you can clean up the branches:

```bash
# List merged branches
git branch --merged origin/master

# Delete merged branches locally
git branch -d <branch-name>

# Delete merged branches remotely
git push origin --delete <branch-name>
```

The advanced sync script can help automate this process.

## Troubleshooting

### Common Issues

#### 1. "Not in a git repository"
Make sure you're in the sigma repository root directory.

#### 2. "Permission denied"
Make sure the sync scripts are executable:
```bash
chmod +x sync_local.sh advanced_sync.sh
```

#### 3. Merge conflicts
If you have local changes that conflict with remote changes:
```bash
# Stash your changes
git stash

# Pull remote changes
git pull origin master

# Apply your changes back
git stash pop
```

#### 4. Can't see new branches
Make sure to fetch all remote changes:
```bash
git fetch --all
```

### Getting Help

If you encounter issues:
1. Check the GitHub Actions logs for workflow errors
2. Run the advanced sync script for detailed diagnostics
3. Check your git configuration and permissions
4. Ensure your GitHub tokens are properly configured

## Best Practices

1. **Sync regularly**: Run the sync script after each workflow execution
2. **Review before merging**: Always review generated rules before merging PRs
3. **Keep branches clean**: Clean up merged branches to avoid clutter
4. **Monitor workflow**: Check workflow logs for any issues
5. **Backup important changes**: If you have local modifications, commit them before syncing

## Automation

You can automate the sync process by:
1. Setting up a cron job to run the sync script periodically
2. Using GitHub webhooks to trigger syncs when workflows complete
3. Creating a post-merge action to clean up branches automatically

## File Structure

After syncing, your repository will have this structure:
```
sigma/
├── rules/
│   ├── *.yml                    # Sigma rules
│   ├── sentinel/
│   │   └── *.kql               # Azure Sentinel queries
│   ├── crowdstrike/
│   │   └── *.falcon            # CrowdStrike queries
│   └── sentinelone/
│       └── *.sql               # SentinelOne queries
├── sync_local.sh               # Basic sync script
├── advanced_sync.sh            # Advanced sync script
└── SYNC_README.md              # This file
``` 