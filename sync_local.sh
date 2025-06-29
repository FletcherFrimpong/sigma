#!/bin/bash

# Sigma Repository Sync Script
# This script helps keep your local repository in sync with remote changes
# Run this script after the GitHub Actions workflow completes

set -e

echo "🔄 Syncing local repository with remote..."

# Get the current branch
CURRENT_BRANCH=$(git branch --show-current)
echo "📍 Current branch: $CURRENT_BRANCH"

# Fetch all changes from remote
echo "📥 Fetching all changes from remote..."
git fetch --all --prune

# Update the current branch
echo "🔄 Updating current branch..."
git pull origin $CURRENT_BRANCH

# List all branches (local and remote)
echo "🌿 All branches:"
git branch -a

# Show recent commits
echo "📝 Recent commits:"
git log --oneline -10

# Show any uncommitted changes
echo "📋 Uncommitted changes:"
git status --porcelain

# Optional: Clean up merged branches
echo "🧹 Cleaning up merged branches..."
git branch --merged | grep -v "\*" | grep -v "master" | grep -v "main" | xargs -n 1 git branch -d 2>/dev/null || true

echo "✅ Sync complete!"
echo ""
echo "💡 Tips:"
echo "  - Run this script after each workflow execution"
echo "  - Check for new branches: git branch -a"
echo "  - Switch to a new branch: git checkout -b <branch-name> origin/<branch-name>"
echo "  - View PR details: git log --oneline origin/master..HEAD" 