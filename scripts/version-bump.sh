#!/bin/bash

# Script for automatic semantic versioning
# Analyzes changes and increments the version appropriately

set -e

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Colored log function
log() {
    echo -e "${GREEN}[VERSION]${NC} $1"
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
    exit 0
fi

log "Modified files:"
echo "$MODIFIED_FILES"

# Analyze changes to determine version type
MAJOR_CHANGES=false
MINOR_CHANGES=false
PATCH_CHANGES=false

# Check for breaking changes (MAJOR)
if echo "$MODIFIED_FILES" | grep -q -E "(build\.gradle|\.java|\.groovy)" && \
   git diff $BASE_REF $HEAD_REF | grep -q -E "(BREAKING CHANGE|breaking change|!:|feat!|fix!)"; then
    MAJOR_CHANGES=true
    log "🔴 MAJOR changes detected (breaking changes)"
fi

# Check for new features (MINOR)
if echo "$MODIFIED_FILES" | grep -q -E "(\.java|\.groovy|\.yaml)" && \
   git diff $BASE_REF $HEAD_REF | grep -q -E "(feat:|feature:|new:|add:)" && \
   [ "$MAJOR_CHANGES" = false ]; then
    MINOR_CHANGES=true
    log "🟡 MINOR changes detected (new features)"
fi

# Check for fixes and improvements (PATCH)
if echo "$MODIFIED_FILES" | grep -q -E "(\.java|\.groovy|\.yaml|\.md|\.txt)" && \
   git diff $BASE_REF $HEAD_REF | grep -q -E "(fix:|bugfix:|patch:|docs:|style:|refactor:|perf:|test:|chore:)" && \
   [ "$MAJOR_CHANGES" = false ] && [ "$MINOR_CHANGES" = false ]; then
    PATCH_CHANGES=true
    log "🟢 PATCH changes detected (fixes and improvements)"
fi

# If no specific changes detected, assume PATCH
if [ "$MAJOR_CHANGES" = false ] && [ "$MINOR_CHANGES" = false ] && [ "$PATCH_CHANGES" = false ]; then
    PATCH_CHANGES=true
    log "🟢 Assuming PATCH changes (default)"
fi

# Read current version from build.gradle
CURRENT_VERSION=$(grep "^version " build.gradle | sed 's/version //' | tr -d "'")

if [ -z "$CURRENT_VERSION" ]; then
    error "Could not get current version from build.gradle"
    exit 1
fi

log "Current version: $CURRENT_VERSION"

# Split version components
IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

# Calculate new version
if [ "$MAJOR_CHANGES" = true ]; then
    NEW_MAJOR=$((MAJOR + 1))
    NEW_MINOR=0
    NEW_PATCH=0
    VERSION_TYPE="MAJOR"
elif [ "$MINOR_CHANGES" = true ]; then
    NEW_MAJOR=$MAJOR
    NEW_MINOR=$((MINOR + 1))
    NEW_PATCH=0
    VERSION_TYPE="MINOR"
else
    NEW_MAJOR=$MAJOR
    NEW_MINOR=$MINOR
    NEW_PATCH=$((PATCH + 1))
    VERSION_TYPE="PATCH"
fi

NEW_VERSION="$NEW_MAJOR.$NEW_MINOR.$NEW_PATCH"

log "New version calculated: $NEW_VERSION ($VERSION_TYPE)"

# Update build.gradle
log "Updating build.gradle..."
sed -i "s/^version '.*'/version '$NEW_VERSION'/" build.gradle

# Check if the change was applied
UPDATED_VERSION=$(grep "^version " build.gradle | sed 's/version //' | tr -d "'")

if [ "$UPDATED_VERSION" = "$NEW_VERSION" ]; then
    log "✅ Version updated successfully: $CURRENT_VERSION → $NEW_VERSION"
else
    error "❌ Failed to update version"
    exit 1
fi

# Create file with version information for workflow use
echo "VERSION_TYPE=$VERSION_TYPE" > .version_info
echo "OLD_VERSION=$CURRENT_VERSION" >> .version_info
echo "NEW_VERSION=$NEW_VERSION" >> .version_info
echo "CHANGES_DETECTED=true" >> .version_info

# Log detected changes
log "📋 Change summary:"
echo "   Version type: $VERSION_TYPE"
echo "   Previous version: $CURRENT_VERSION"
echo "   New version: $NEW_VERSION"
echo "   Modified files: $(echo "$MODIFIED_FILES" | wc -l)"

# If PR, do not commit automatically
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    log "📝 Pull Request detected - version will be updated on merge"
    echo "PR_DETECTED=true" >> .version_info
else
    log "🚀 Direct push detected - preparing commit for new version"
    echo "PR_DETECTED=false" >> .version_info
fi

log "✅ Semantic versioning completed!" 