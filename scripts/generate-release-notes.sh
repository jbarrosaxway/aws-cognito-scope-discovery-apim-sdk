#!/bin/bash

# Script to generate intelligent release notes based on commits
# Analyzes commit history and creates detailed release notes

set -e

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Colored log function
log() {
    echo -e "${GREEN}[RELEASE-NOTES]${NC} $1"
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

# Get parameters
PREVIOUS_TAG="$1"
NEW_TAG="$2"
RELEASE_VERSION="$3"

if [ -z "$PREVIOUS_TAG" ] || [ -z "$NEW_TAG" ] || [ -z "$RELEASE_VERSION" ]; then
    error "Usage: $0 <previous_tag> <new_tag> <release_version>"
    exit 1
fi

log "Generating release notes from $PREVIOUS_TAG to $NEW_TAG"

# Get commit range
if [ "$PREVIOUS_TAG" = "none" ]; then
    COMMIT_RANGE="HEAD"
else
    COMMIT_RANGE="$PREVIOUS_TAG..$NEW_TAG"
fi

# Get commits in range
COMMITS=$(git log --pretty=format:"%h|%s|%an|%ad" --date=short "$COMMIT_RANGE")

if [ -z "$COMMITS" ]; then
    warn "No commits found in range $COMMIT_RANGE"
    echo "# Release v$RELEASE_VERSION" > .release_notes
    echo "" >> .release_notes
    echo "No changes detected in this release." >> .release_notes
    exit 0
fi

# Initialize release notes
echo "# Release v$RELEASE_VERSION" > .release_notes
echo "" >> .release_notes
echo "## 📋 Summary" >> .release_notes
echo "" >> .release_notes

# Count commits by type
FEATURES=0
FIXES=0
DOCS=0
REFACTOR=0
CHORE=0
BREAKING=0
OTHER=0

# Analyze commits and categorize
while IFS='|' read -r hash message author date; do
    # Convert to lowercase for easier matching
    lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
    
    # Check for breaking changes
    if echo "$lower_message" | grep -q -E "(breaking change|breaking|!:|feat!|fix!)"; then
        BREAKING=$((BREAKING + 1))
    elif echo "$lower_message" | grep -q -E "^feat:|^feature:|^new:|^add:"; then
        FEATURES=$((FEATURES + 1))
    elif echo "$lower_message" | grep -q -E "^fix:|^bugfix:|^patch:"; then
        FIXES=$((FIXES + 1))
    elif echo "$lower_message" | grep -q -E "^docs:|^doc:"; then
        DOCS=$((DOCS + 1))
    elif echo "$lower_message" | grep -q -E "^refactor:|^perf:"; then
        REFACTOR=$((REFACTOR + 1))
    elif echo "$lower_message" | grep -q -E "^chore:|^build:|^ci:"; then
        CHORE=$((CHORE + 1))
    else
        OTHER=$((OTHER + 1))
    fi
done <<< "$COMMITS"

# Write summary
TOTAL=$((FEATURES + FIXES + DOCS + REFACTOR + CHORE + BREAKING + OTHER))
echo "This release includes **$TOTAL** commits with the following changes:" >> .release_notes
echo "" >> .release_notes

if [ $BREAKING -gt 0 ]; then
    echo "🚨 **$BREAKING breaking change(s)**" >> .release_notes
fi
if [ $FEATURES -gt 0 ]; then
    echo "✨ **$FEATURES new feature(s)**" >> .release_notes
fi
if [ $FIXES -gt 0 ]; then
    echo "🐛 **$FIXES bug fix(es)**" >> .release_notes
fi
if [ $REFACTOR -gt 0 ]; then
    echo "🔧 **$REFACTOR improvement(s)**" >> .release_notes
fi
if [ $DOCS -gt 0 ]; then
    echo "📚 **$DOCS documentation update(s)**" >> .release_notes
fi
if [ $CHORE -gt 0 ]; then
    echo "⚙️ **$CHORE maintenance task(s)**" >> .release_notes
fi
if [ $OTHER -gt 0 ]; then
    echo "📝 **$OTHER other change(s)**" >> .release_notes
fi

echo "" >> .release_notes
echo "---" >> .release_notes
echo "" >> .release_notes

# Detailed changes section
echo "## 🔍 Detailed Changes" >> .release_notes
echo "" >> .release_notes

# Breaking changes
if [ $BREAKING -gt 0 ]; then
    echo "### 🚨 Breaking Changes" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "(breaking change|breaking|!:|feat!|fix!)"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# New features
if [ $FEATURES -gt 0 ]; then
    echo "### ✨ New Features" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "^feat:|^feature:|^new:|^add:"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Bug fixes
if [ $FIXES -gt 0 ]; then
    echo "### 🐛 Bug Fixes" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "^fix:|^bugfix:|^patch:"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Improvements
if [ $REFACTOR -gt 0 ]; then
    echo "### 🔧 Improvements" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "^refactor:|^perf:"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Documentation
if [ $DOCS -gt 0 ]; then
    echo "### 📚 Documentation" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "^docs:|^doc:"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Maintenance
if [ $CHORE -gt 0 ]; then
    echo "### ⚙️ Maintenance" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if echo "$lower_message" | grep -q -E "^chore:|^build:|^ci:"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Other changes
if [ $OTHER -gt 0 ]; then
    echo "### 📝 Other Changes" >> .release_notes
    echo "" >> .release_notes
    while IFS='|' read -r hash message author date; do
        lower_message=$(echo "$message" | tr '[:upper:]' '[:lower:]')
        if ! echo "$lower_message" | grep -q -E "(breaking change|breaking|!:|feat!|fix!|^feat:|^feature:|^new:|^add:|^fix:|^bugfix:|^patch:|^docs:|^doc:|^refactor:|^perf:|^chore:|^build:|^ci:)"; then
            echo "- **$message** ([$hash](https://github.com/$GITHUB_REPOSITORY/commit/$hash)) - $author" >> .release_notes
        fi
    done <<< "$COMMITS"
    echo "" >> .release_notes
fi

# Add technical details section
echo "## 🔧 Technical Details" >> .release_notes
echo "" >> .release_notes
echo "- **Release Date:** $(date +%Y-%m-%d)" >> .release_notes
echo "- **Commit Range:** $COMMIT_RANGE" >> .release_notes
echo "- **Total Commits:** $TOTAL" >> .release_notes
echo "- **Contributors:** $(echo "$COMMITS" | cut -d'|' -f3 | sort -u | wc -l)" >> .release_notes
echo "" >> .release_notes

# Add detailed change analysis if available
if [ -f scripts/analyze-changes.sh ]; then
    log "Running detailed change analysis..."
    chmod +x scripts/analyze-changes.sh
    ./scripts/analyze-changes.sh "$COMMIT_RANGE" > .change_analysis 2>/dev/null || true
    
    if [ -f .change_analysis ] && [ -s .change_analysis ]; then
        echo "## 📊 Change Analysis" >> .release_notes
        echo "" >> .release_notes
        cat .change_analysis >> .release_notes
        echo "" >> .release_notes
    fi
fi

# Add installation section
echo "## 📦 Installation" >> .release_notes
echo "" >> .release_notes
echo "### Linux" >> .release_notes
echo "1. Download the ZIP file for your Axway version" >> .release_notes
echo "2. Extract and set AXWAY_HOME environment variable" >> .release_notes
echo "3. Run: \`./install-linux.sh\`" >> .release_notes
echo "" >> .release_notes
echo "### Windows" >> .release_notes
echo "1. Download the ZIP file for your Axway version" >> .release_notes
echo "2. Extract and open command prompt in the directory" >> .release_notes
echo "3. Run: \`./gradlew \"-Dproject.path=C:\\path\\to\\your\\project\" installWindowsToProject\`" >> .release_notes
echo "" >> .release_notes

# Add compatibility section
echo "## ✅ Compatibility" >> .release_notes
echo "" >> .release_notes
echo "This release is compatible with the following Axway API Gateway versions:" >> .release_notes
echo "- 7.7.0.20240830" >> .release_notes
echo "- Additional versions as specified in the release ZIPs" >> .release_notes
echo "" >> .release_notes

# Add contributors section
echo "## 👥 Contributors" >> .release_notes
echo "" >> .release_notes
CONTRIBUTORS=$(echo "$COMMITS" | cut -d'|' -f3 | sort -u | sed 's/^/- /')
echo "$CONTRIBUTORS" >> .release_notes
echo "" >> .release_notes

# Add links section
echo "## 🔗 Links" >> .release_notes
echo "" >> .release_notes
echo "- [Full Changelog](https://github.com/$GITHUB_REPOSITORY/compare/$PREVIOUS_TAG...$NEW_TAG)" >> .release_notes
echo "- [Documentation](https://github.com/$GITHUB_REPOSITORY/blob/$NEW_TAG/README.md)" >> .release_notes
echo "- [Installation Guide](https://github.com/$GITHUB_REPOSITORY/blob/$NEW_TAG/docs/INSTALLATION.md)" >> .release_notes
echo "" >> .release_notes

log "✅ Release notes generated successfully!"
log "📋 Summary: $TOTAL commits ($FEATURES features, $FIXES fixes, $BREAKING breaking changes)"

# Output the release notes
cat .release_notes 