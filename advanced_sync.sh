#!/bin/bash

# Advanced Sigma Repository Sync Script
# This script provides comprehensive synchronization and branch management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}🔄 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository. Please run this script from the sigma repository root."
        exit 1
    fi
}

# Function to sync with remote
sync_with_remote() {
    print_status "Syncing with remote repository..."
    
    # Get current branch
    CURRENT_BRANCH=$(git branch --show-current)
    print_status "Current branch: $CURRENT_BRANCH"
    
    # Fetch all changes
    git fetch --all --prune
    
    # Update current branch
    if git pull origin $CURRENT_BRANCH; then
        print_success "Successfully updated current branch"
    else
        print_warning "Could not update current branch (may have conflicts)"
    fi
}

# Function to show branch information
show_branches() {
    print_status "Branch Information:"
    echo ""
    
    # Show local branches
    echo "Local branches:"
    git branch --format='%(HEAD) %(color:yellow)%(refname:short)%(color:reset) - %(contents:subject)'
    echo ""
    
    # Show remote branches
    echo "Remote branches:"
    git branch -r --format='%(refname:short) - %(contents:subject)'
    echo ""
}

# Function to show recent activity
show_recent_activity() {
    print_status "Recent Activity:"
    echo ""
    
    # Show recent commits
    echo "Recent commits (last 10):"
    git log --oneline -10 --graph --decorate
    echo ""
    
    # Show uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        print_warning "You have uncommitted changes:"
        git status --short
        echo ""
    else
        print_success "Working directory is clean"
    fi
}

# Function to manage auto-generated branches
manage_auto_branches() {
    print_status "Managing auto-generated branches..."
    
    # List auto-generated branches
    AUTO_BRANCHES=$(git branch -r | grep "origin/auto/" | sed 's/origin\///')
    
    if [ -z "$AUTO_BRANCHES" ]; then
        print_success "No auto-generated branches found"
        return
    fi
    
    echo "Auto-generated branches:"
    echo "$AUTO_BRANCHES"
    echo ""
    
    # Check which branches have been merged
    MERGED_BRANCHES=""
    for branch in $AUTO_BRANCHES; do
        if git branch -r --merged origin/master | grep -q "origin/$branch"; then
            MERGED_BRANCHES="$MERGED_BRANCHES $branch"
        fi
    done
    
    if [ -n "$MERGED_BRANCHES" ]; then
        print_warning "Merged auto-branches (can be cleaned up):"
        echo "$MERGED_BRANCHES"
        echo ""
        
        read -p "Do you want to delete merged auto-branches? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for branch in $MERGED_BRANCHES; do
                print_status "Deleting merged branch: $branch"
                git push origin --delete $branch 2>/dev/null || print_warning "Could not delete remote branch $branch"
            done
            print_success "Cleanup complete"
        fi
    fi
}

# Function to show PR information
show_pr_info() {
    print_status "Pull Request Information:"
    echo ""
    
    # Get the repository URL
    REPO_URL=$(git config --get remote.origin.url)
    if [[ $REPO_URL == *"github.com"* ]]; then
        # Extract owner and repo from URL
        if [[ $REPO_URL == *"git@github.com:"* ]]; then
            REPO_PATH=$(echo $REPO_URL | sed 's/git@github.com://' | sed 's/\.git$//')
        else
            REPO_PATH=$(echo $REPO_URL | sed 's/https:\/\/github.com\///' | sed 's/\.git$//')
        fi
        
        echo "Repository: $REPO_PATH"
        echo "Open PRs: https://github.com/$REPO_PATH/pulls"
        echo ""
    fi
}

# Function to switch to a specific branch
switch_to_branch() {
    if [ -n "$1" ]; then
        BRANCH_NAME=$1
        print_status "Switching to branch: $BRANCH_NAME"
        
        # Check if branch exists locally
        if git show-ref --verify --quiet refs/heads/$BRANCH_NAME; then
            git checkout $BRANCH_NAME
            print_success "Switched to local branch: $BRANCH_NAME"
        # Check if branch exists remotely
        elif git show-ref --verify --quiet refs/remotes/origin/$BRANCH_NAME; then
            git checkout -b $BRANCH_NAME origin/$BRANCH_NAME
            print_success "Switched to remote branch: $BRANCH_NAME"
        else
            print_error "Branch $BRANCH_NAME not found"
            return 1
        fi
    fi
}

# Main execution
main() {
    echo "🚀 Advanced Sigma Repository Sync"
    echo "=================================="
    echo ""
    
    # Check if we're in a git repository
    check_git_repo
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --branch|-b)
                switch_to_branch "$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -b, --branch BRANCH    Switch to specified branch"
                echo "  -h, --help            Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                    # Full sync and status"
                echo "  $0 -b auto/multi_platform_abc123  # Switch to specific branch"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Perform sync operations
    sync_with_remote
    echo ""
    
    show_branches
    show_recent_activity
    manage_auto_branches
    show_pr_info
    
    print_success "Sync and analysis complete!"
    echo ""
    echo "💡 Next steps:"
    echo "  - Review generated rules in the rules/ directory"
    echo "  - Check PR status on GitHub"
    echo "  - Merge PRs when ready"
    echo "  - Run this script again to stay in sync"
}

# Run main function with all arguments
main "$@" 