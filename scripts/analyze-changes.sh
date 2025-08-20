#!/bin/bash

# Script to analyze specific code changes and detect detailed change types
# Provides additional context for release notes

set -e

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Colored log function
log() {
    echo -e "${GREEN}[ANALYZE]${NC} $1"
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
COMMIT_RANGE="$1"

if [ -z "$COMMIT_RANGE" ]; then
    error "Usage: $0 <commit_range>"
    exit 1
fi

log "Analyzing changes in range: $COMMIT_RANGE"

# Initialize analysis results
echo "# Change Analysis" > .change_analysis
echo "" >> .change_analysis

# Get modified files
MODIFIED_FILES=$(git diff --name-only "$COMMIT_RANGE" 2>/dev/null || echo "")

if [ -z "$MODIFIED_FILES" ]; then
    warn "No modified files found in range $COMMIT_RANGE"
    echo "No changes detected." >> .change_analysis
    exit 0
fi

# Analyze file types
JAVA_FILES=0
GRADLE_FILES=0
DOCKER_FILES=0
SCRIPT_FILES=0
DOC_FILES=0
CONFIG_FILES=0
WORKFLOW_FILES=0

# Categorize files
for file in $MODIFIED_FILES; do
    case "$file" in
        *.java)
            JAVA_FILES=$((JAVA_FILES + 1))
            ;;
        build.gradle|gradle/*|gradlew*|settings.gradle)
            GRADLE_FILES=$((GRADLE_FILES + 1))
            ;;
        Dockerfile|docker-compose*)
            DOCKER_FILES=$((DOCKER_FILES + 1))
            ;;
        *.sh|*.bat|*.ps1|*.cmd)
            SCRIPT_FILES=$((SCRIPT_FILES + 1))
            ;;
        *.md|docs/*)
            DOC_FILES=$((DOC_FILES + 1))
            ;;
        *.yml|*.yaml|*.xml|*.properties|*.json)
            CONFIG_FILES=$((CONFIG_FILES + 1))
            ;;
        .github/workflows/*)
            WORKFLOW_FILES=$((WORKFLOW_FILES + 1))
            ;;
    esac
done

# Write file analysis
echo "## 📁 File Changes" >> .change_analysis
echo "" >> .change_analysis
TOTAL_FILES=$(echo "$MODIFIED_FILES" | wc -l)
echo "**Total files modified:** $TOTAL_FILES" >> .change_analysis
echo "" >> .change_analysis

if [ $JAVA_FILES -gt 0 ]; then
    echo "- **Java files:** $JAVA_FILES" >> .change_analysis
fi
if [ $GRADLE_FILES -gt 0 ]; then
    echo "- **Gradle files:** $GRADLE_FILES" >> .change_analysis
fi
if [ $DOCKER_FILES -gt 0 ]; then
    echo "- **Docker files:** $DOCKER_FILES" >> .change_analysis
fi
if [ $SCRIPT_FILES -gt 0 ]; then
    echo "- **Script files:** $SCRIPT_FILES" >> .change_analysis
fi
if [ $DOC_FILES -gt 0 ]; then
    echo "- **Documentation files:** $DOC_FILES" >> .change_analysis
fi
if [ $CONFIG_FILES -gt 0 ]; then
    echo "- **Configuration files:** $CONFIG_FILES" >> .change_analysis
fi
if [ $WORKFLOW_FILES -gt 0 ]; then
    echo "- **Workflow files:** $WORKFLOW_FILES" >> .change_analysis
fi

echo "" >> .change_analysis

# Analyze specific changes in Java files
if [ $JAVA_FILES -gt 0 ]; then
    echo "## 🔍 Java Code Analysis" >> .change_analysis
    echo "" >> .change_analysis
    
    # Check for new methods
    NEW_METHODS=$(git diff "$COMMIT_RANGE" -- "*.java" | grep -c "+.*public.*(" || echo "0")
    if [ "$NEW_METHODS" -gt 0 ]; then
        echo "- **New methods added:** $NEW_METHODS" >> .change_analysis
    fi
    
    # Check for removed methods
    REMOVED_METHODS=$(git diff "$COMMIT_RANGE" -- "*.java" | grep -c "-.*public.*(" || echo "0")
    if [ "$REMOVED_METHODS" -gt 0 ]; then
        echo "- **Methods removed:** $REMOVED_METHODS" >> .change_analysis
    fi
    
    # Check for new classes
    NEW_CLASSES=$(git diff "$COMMIT_RANGE" -- "*.java" | grep -c "+.*class.*{" || echo "0")
    if [ "$NEW_CLASSES" -gt 0 ]; then
        echo "- **New classes added:** $NEW_CLASSES" >> .change_analysis
    fi
    
    # Check for removed classes
    REMOVED_CLASSES=$(git diff "$COMMIT_RANGE" -- "*.java" | grep -c "-.*class.*{" || echo "0")
    if [ "$REMOVED_CLASSES" -gt 0 ]; then
        echo "- **Classes removed:** $REMOVED_CLASSES" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Analyze build system changes
if [ $GRADLE_FILES -gt 0 ]; then
    echo "## 🔧 Build System Changes" >> .change_analysis
    echo "" >> .change_analysis
    
    # Check for dependency changes
    DEPENDENCY_CHANGES=$(git diff "$COMMIT_RANGE" -- "build.gradle" | grep -c "implementation\|compile\|runtime" || echo "0")
    if [ "$DEPENDENCY_CHANGES" -gt 0 ]; then
        echo "- **Dependency changes:** $DEPENDENCY_CHANGES" >> .change_analysis
    fi
    
    # Check for version changes
    VERSION_CHANGES=$(git diff "$COMMIT_RANGE" -- "build.gradle" | grep -c "version" || echo "0")
    if [ "$VERSION_CHANGES" -gt 0 ]; then
        echo "- **Version updates:** $VERSION_CHANGES" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Analyze Docker changes
if [ $DOCKER_FILES -gt 0 ]; then
    echo "## 🐳 Docker Changes" >> .change_analysis
    echo "" >> .change_analysis
    
    # Check for base image changes
    BASE_IMAGE_CHANGES=$(git diff "$COMMIT_RANGE" -- "Dockerfile" | grep -c "FROM" || echo "0")
    if [ "$BASE_IMAGE_CHANGES" -gt 0 ]; then
        echo "- **Base image changes:** $BASE_IMAGE_CHANGES" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Analyze workflow changes
if [ $WORKFLOW_FILES -gt 0 ]; then
    echo "## ⚙️ CI/CD Changes" >> .change_analysis
    echo "" >> .change_analysis
    
    # Check for workflow modifications
    WORKFLOW_MODS=$(git diff "$COMMIT_RANGE" -- ".github/workflows/" | wc -l || echo "0")
    if [ "$WORKFLOW_MODS" -gt 0 ]; then
        echo "- **Workflow modifications:** $WORKFLOW_MODS lines" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Analyze documentation changes
if [ $DOC_FILES -gt 0 ]; then
    echo "## 📚 Documentation Changes" >> .change_analysis
    echo "" >> .change_analysis
    
    # Count documentation files
    echo "- **Documentation files modified:** $DOC_FILES" >> .change_analysis
    
    # Check for README changes
    if echo "$MODIFIED_FILES" | grep -q "README.md"; then
        echo "- **README.md updated**" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Detect breaking changes
BREAKING_INDICATORS=0

# Check for removed public methods/classes
if [ "$REMOVED_METHODS" -gt 0 ] || [ "$REMOVED_CLASSES" -gt 0 ]; then
    BREAKING_INDICATORS=$((BREAKING_INDICATORS + 1))
fi

# Check for API changes in build.gradle
API_CHANGES=$(git diff "$COMMIT_RANGE" -- "build.gradle" | grep -c "api\|public" || echo "0")
if [ "$API_CHANGES" -gt 0 ]; then
    BREAKING_INDICATORS=$((BREAKING_INDICATORS + 1))
fi

if [ $BREAKING_INDICATORS -gt 0 ]; then
    echo "## 🚨 Breaking Change Indicators" >> .change_analysis
    echo "" >> .change_analysis
    echo "⚠️ **Potential breaking changes detected:**" >> .change_analysis
    echo "" >> .change_analysis
    
    if [ "$REMOVED_METHODS" -gt 0 ]; then
        echo "- $REMOVED_METHODS public method(s) removed" >> .change_analysis
    fi
    if [ "$REMOVED_CLASSES" -gt 0 ]; then
        echo "- $REMOVED_CLASSES class(es) removed" >> .change_analysis
    fi
    if [ "$API_CHANGES" -gt 0 ]; then
        echo "- API configuration changes detected" >> .change_analysis
    fi
    
    echo "" >> .change_analysis
fi

# Add summary
echo "## 📊 Summary" >> .change_analysis
echo "" >> .change_analysis
echo "**Change Impact Assessment:**" >> .change_analysis
echo "" >> .change_analysis

if [ $JAVA_FILES -gt 0 ]; then
    echo "- **Code Changes:** High impact" >> .change_analysis
fi
if [ $GRADLE_FILES -gt 0 ]; then
    echo "- **Build Changes:** Medium impact" >> .change_analysis
fi
if [ $DOC_FILES -gt 0 ]; then
    echo "- **Documentation:** Low impact" >> .change_analysis
fi
if [ $WORKFLOW_FILES -gt 0 ]; then
    echo "- **CI/CD Changes:** Medium impact" >> .change_analysis
fi

echo "" >> .change_analysis

log "✅ Change analysis completed!"
log "📋 Summary: $TOTAL_FILES files modified ($JAVA_FILES Java, $GRADLE_FILES Gradle, $DOC_FILES docs)"

# Output the analysis
cat .change_analysis 