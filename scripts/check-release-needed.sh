#!/bin/bash

# Script to check if a release is needed
# Analyzes changes and determines if a release should be created

set -e

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Colored log function
log() {
    echo -e "${GREEN}[RELEASE-CHECK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if we are in a PR or direct push
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    log "Analyzing changes in Pull Request..."
    BASE_REF="$GITHUB_BASE_REF"
    HEAD_REF="$GITHUB_HEAD_REF"
else
    log "Analyzing changes in direct push..."
    BASE_REF="HEAD~1"
    HEAD_REF="HEAD"
fi

# Get list of modified files
log "Getting modified files..."
MODIFIED_FILES=$(git diff --name-only $BASE_REF $HEAD_REF || echo "")

if [ -z "$MODIFIED_FILES" ]; then
    warn "No modified files found"
    echo "RELEASE_NEEDED=false" > .release_check
    exit 0
fi

log "Modified files:"
echo "$MODIFIED_FILES"

# Define files that should NOT trigger a release
NON_RELEASE_FILES=(
    "README.md"
    "docs/"
    ".md$"
    ".gitignore"
    ".github/"
    "LICENSE"
    "*.txt"
    "*.log"
    "*.bak"
    "*.backup"
    "*.tmp"
    "*.temp"
    "*.swp"
    "*.swo"
    "*~"
    ".DS_Store"
    "Thumbs.db"
    "*.iml"
    "*.ipr"
    "*.iws"
    ".project"
    ".classpath"
    ".settings/"
    ".idea/"
    ".vscode/"
    "node_modules/"
    "__pycache__/"
    "*.pyc"
    "*.pyo"
    "*.pyd"
    "*.so"
    ".Python"
    "env/"
    "venv/"
    "ENV/"
    "env.bak/"
    "venv.bak/"
    "test-results/"
    "coverage/"
    ".coverage"
    "*.docx"
    "*.doc"
    "*.pdf"
    "*.run"
    "license.txt"
)

# Define files that SHOULD trigger a release
RELEASE_FILES=(
    "src/"
    "build.gradle"
    "gradle/"
    "gradlew"
    "gradlew.bat"
    "settings.gradle"
    "Dockerfile"
    "docker-compose"
    "axway-versions.json"
    "*.java"
    "*.groovy"
    "*.yaml"
    "*.yml"
    "*.xml"
    "*.properties"
    "*.sh"
    "*.ps1"
    "*.cmd"
    "*.bat"
)

# Function to check if a file should trigger a release
should_generate_release() {
    local file="$1"
    
    # Check if it is a file that should NOT trigger a release
    for pattern in "${NON_RELEASE_FILES[@]}"; do
        if [[ "$file" =~ $pattern ]]; then
            return 1  # false - should not trigger release
        fi
    done
    
    # Check if it is a file that SHOULD trigger a release
    for pattern in "${RELEASE_FILES[@]}"; do
        if [[ "$file" =~ $pattern ]]; then
            return 0  # true - should trigger release
        fi
    done
    
    # If not in any list, check extension
    local ext="${file##*.}"
    case "$ext" in
        java|groovy|yaml|yml|xml|properties|sh|ps1|cmd|bat|gradle)
            return 0  # true - should trigger release
            ;;
        md|txt|log|bak|backup|tmp|temp|swp|swo|iml|ipr|iws|docx|doc|pdf|run)
            return 1  # false - should not trigger release
            ;;
        *)
            # If no extension or unknown, check if in src/
            if [[ "$file" == src/* ]]; then
                return 0  # true - should trigger release
            else
                return 1  # false - should not trigger release
            fi
            ;;
    esac
}

# Analyze modified files
RELEASE_NEEDED=false
RELEVANT_FILES=""

log "Analyzing relevance of changes..."

for file in $MODIFIED_FILES; do
    if should_generate_release "$file"; then
        RELEASE_NEEDED=true
        RELEVANT_FILES="$RELEVANT_FILES $file"
        log "✅ Relevant for release: $file"
    else
        log "⏭️  Not relevant for release: $file"
    fi
done

# Check if there are relevant changes
if [ "$RELEASE_NEEDED" = true ]; then
    log "🔴 Release needed detected!"
    log "📋 Relevant files:$RELEVANT_FILES"
    
    # Run semantic versioning
    log "🔍 Running semantic versioning..."
    ./scripts/version-bump.sh
    
    if [ -f .version_info ]; then
        source .version_info
        log "📊 Version information:"
        log "   Type: $VERSION_TYPE"
        log "   Previous version: $OLD_VERSION"
        log "   New version: $NEW_VERSION"
        
        # Create file with information for the workflow
        echo "RELEASE_NEEDED=true" > .release_check
        echo "VERSION_TYPE=$VERSION_TYPE" >> .release_check
        echo "OLD_VERSION=$OLD_VERSION" >> .release_check
        echo "NEW_VERSION=$NEW_VERSION" >> .release_check
        echo "RELEVANT_FILES='$RELEVANT_FILES'" >> .release_check
        echo "CHANGES_DETECTED=$CHANGES_DETECTED" >> .release_check
        echo "PR_DETECTED=$PR_DETECTED" >> .release_check
    else
        error "❌ Failed to run semantic versioning"
        echo "RELEASE_NEEDED=false" > .release_check
        exit 1
    fi
else
    log "🟢 No relevant changes for release detected"
    echo "RELEASE_NEEDED=false" > .release_check
    echo "RELEVANT_FILES=''" >> .release_check
fi

log "✅ Release analysis completed!" 