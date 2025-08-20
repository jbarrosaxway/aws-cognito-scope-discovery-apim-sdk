#!/bin/bash

# Script to build the JAR using the published image
# axwayjbarros/aws-lambda-apim-sdk:1.0.0
# 
# This image contains all Axway API Gateway libraries
# for building the project, not for runtime.

set -e

echo "🚀 Building JAR using Docker image: axwayjbarros/aws-lambda-apim-sdk:1.0.0"
echo "📋 Note: This image contains only the libraries for build, not for runtime"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Start Docker and try again."
    exit 1
fi

# Check if we are in the correct directory
if [ ! -f "build.gradle" ]; then
    echo "❌ build.gradle file not found. Run this script in the project root directory."
    exit 1
fi

# Pull the image if needed
echo "📥 Checking Docker image..."
docker pull axwayjbarros/aws-lambda-apim-sdk:1.0.0

# Clean previous build
echo ""
echo "🧹 Cleaning previous build..."
rm -rf build/
rm -rf .gradle/

# Create build directory
mkdir -p build/libs

# Build using Docker image
echo ""
echo "🔨 Starting JAR build..."
echo "📁 Current directory: $(pwd)"
echo "📁 Build will be saved in: $(pwd)/build/libs/"

# Run build inside the container
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/build:/workspace/build" \
  -v "$(pwd)/.gradle:/workspace/.gradle" \
  -w /workspace \
  axwayjbarros/aws-lambda-apim-sdk:1.0.0 \
  bash -c "
    echo '🔧 Setting up environment...'
    export JAVA_HOME=/opt/java/openjdk-11
    export PATH=\$JAVA_HOME/bin:\$PATH
    
    echo '📦 Checking Java...'
    java -version
    
    echo '📦 Checking Gradle...'
    gradle --version || echo 'Gradle not found, installing...'
    
    echo '🔨 Running build...'
    gradle clean build || echo 'Build failed, trying without clean...'
    gradle build || echo 'Build failed again'
    
    echo '📋 Checking result...'
    ls -la build/libs/ || echo 'build/libs directory not found'
  "

# Check if the JAR was created
echo ""
echo "🔍 Checking build result..."

if [ -f "build/libs/aws-lambda-apim-sdk-1.0.1.jar" ]; then
    echo "✅ JAR created successfully!"
    echo "📁 File: build/libs/aws-lambda-apim-sdk-1.0.1.jar"
    echo "📏 Size: $(du -h build/libs/aws-lambda-apim-sdk-1.0.1.jar | cut -f1)"
    
    echo ""
    echo "📋 JAR contents:"
    jar -tf build/libs/aws-lambda-apim-sdk-1.0.1.jar | head -20
    
    echo ""
    echo "🎉 Build completed successfully!"
    echo ""
    echo "📋 Next steps:"
    echo "1. For Linux: ./gradlew installLinux"
    echo "2. For Windows: Copy the JAR and run ./gradlew installWindows"
    echo "3. For Docker: docker-compose up -d"
    
else
    echo "❌ JAR was not created!"
    echo ""
    echo "🔍 Checking build directory:"
    ls -la build/ || echo "build directory does not exist"
    
    echo ""
    echo "🔍 Checking Gradle logs:"
    if [ -f ".gradle/build.log" ]; then
        tail -20 .gradle/build.log
    else
        echo "Gradle log not found"
    fi
    
    echo ""
    echo "💡 Troubleshooting suggestions:"
    echo "1. Check if Docker is running"
    echo "2. Check if the image exists: docker images axwayjbarros/aws-lambda-apim-sdk:1.0.0"
    echo "3. Try pulling the image: docker pull axwayjbarros/aws-lambda-apim-sdk:1.0.0"
    echo "4. Check for disk space"
fi 