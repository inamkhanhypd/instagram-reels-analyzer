#!/bin/bash

# Instagram Reels Analyzer - Development Helper Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Instagram Reels Analyzer - Development Helper${NC}"
echo "=================================================="

# Function to show current status
show_status() {
    echo -e "\n${YELLOW}📊 Current Status:${NC}"
    echo "Branch: $(git branch --show-current)"
    echo "Version: $(python3 -c "from version import VERSION; print(VERSION)")"
    echo "Last commit: $(git log -1 --pretty=format:'%h - %s (%cr)')"
}

# Function to start development
start_dev() {
    echo -e "\n${GREEN}🔧 Starting Development Mode${NC}"
    git checkout develop
    echo "✅ Switched to develop branch"
    show_status
}

# Function to test locally
test_local() {
    echo -e "\n${GREEN}🧪 Testing Locally${NC}"
    echo "Starting Streamlit development server..."
    echo "Press Ctrl+C to stop the server"
    streamlit run app.py
}

# Function to create feature branch
create_feature() {
    if [ -z "$1" ]; then
        echo -e "${RED}❌ Please provide a feature name${NC}"
        echo "Usage: ./dev-helper.sh feature my-new-feature"
        exit 1
    fi
    
    feature_name="feature/$1"
    echo -e "\n${GREEN}🌿 Creating Feature Branch: $feature_name${NC}"
    git checkout develop
    git checkout -b "$feature_name"
    echo "✅ Created and switched to $feature_name"
    show_status
}

# Function to merge to develop
merge_to_develop() {
    echo -e "\n${GREEN}🔄 Merging to Develop${NC}"
    current_branch=$(git branch --show-current)
    
    if [[ $current_branch == develop ]]; then
        echo -e "${RED}❌ Already on develop branch${NC}"
        exit 1
    fi
    
    git checkout develop
    git merge "$current_branch"
    git push origin develop
    echo "✅ Merged $current_branch to develop"
    show_status
}

# Function to deploy to production
deploy_production() {
    echo -e "\n${GREEN}🚀 Deploying to Production${NC}"
    git checkout main
    git merge develop
    git push origin main
    echo "✅ Deployed to production (Railway)"
    show_status
}

# Function to show help
show_help() {
    echo -e "\n${YELLOW}📖 Available Commands:${NC}"
    echo "  start          - Switch to develop branch"
    echo "  test           - Run local development server"
    echo "  feature <name> - Create new feature branch"
    echo "  merge          - Merge current branch to develop"
    echo "  deploy         - Deploy develop to production"
    echo "  status         - Show current status"
    echo "  help           - Show this help"
}

# Main script logic
case "$1" in
    "start")
        start_dev
        ;;
    "test")
        test_local
        ;;
    "feature")
        create_feature "$2"
        ;;
    "merge")
        merge_to_develop
        ;;
    "deploy")
        deploy_production
        ;;
    "status")
        show_status
        ;;
    "help"|"")
        show_help
        ;;
    *)
        echo -e "${RED}❌ Unknown command: $1${NC}"
        show_help
        ;;
esac
