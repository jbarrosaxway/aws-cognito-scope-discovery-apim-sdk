#!/bin/bash

# Invoke Lambda Function installation script for Axway API Gateway (Linux)
# Author: Assistant
# Date: $(date)
# Note: YAML files are organized in src/main/resources/yaml/
# For Windows, use: install-filter-windows.ps1 or install-filter-windows.cmd

AXWAY_DIR="/opt/axway/Axway-7.7.0.20240830"
JAR_FILE="build/libs/aws-lambda-apim-sdk-1.0.1.jar"
EXT_LIB_DIR="$AXWAY_DIR/apigateway/groups/group-2/instance-1/ext/lib"

echo "=== Invoke Lambda Function Installation for Axway API Gateway ==="
echo "Axway directory: $AXWAY_DIR"
echo "JAR: $JAR_FILE"
echo ""

# Check if the JAR exists
if [ ! -f "$JAR_FILE" ]; then
    echo "❌ Error: JAR not found: $JAR_FILE"
    echo "Run './gradlew build' first"
    exit 1
fi

# Check if the Axway directory exists
if [ ! -d "$AXWAY_DIR" ]; then
    echo "❌ Error: Axway directory not found: $AXWAY_DIR"
    exit 1
fi

# Create ext/lib directory if it does not exist
if [ ! -d "$EXT_LIB_DIR" ]; then
    echo "📁 Creating directory: $EXT_LIB_DIR"
    mkdir -p "$EXT_LIB_DIR"
fi

# Copy JAR to ext/lib directory
echo "📦 Copying JAR to: $EXT_LIB_DIR"
cp "$JAR_FILE" "$EXT_LIB_DIR/"

# Check if the copy was successful
if [ $? -eq 0 ]; then
    echo "✅ JAR copied successfully"
else
    echo "❌ Error copying JAR"
    exit 1
fi

# List JARs in the directory
echo ""
echo "📋 JARs in ext/lib directory:"
ls -la "$EXT_LIB_DIR"/*.jar

echo ""
echo "=== Installation Completed ==="
echo ""
echo "📝 Next steps:"
echo "1. Restart Axway API Gateway"
echo "2. In Policy Studio, go to Window > Preferences > Runtime Dependencies"
echo "3. Add the JAR: $EXT_LIB_DIR/aws-lambda-apim-sdk-1.0.1.jar"
echo "4. Restart Policy Studio with the -clean option"
echo "5. The 'Invoke Lambda Function' will be available in the filter palette"
echo ""
echo "🔧 To check if the filter is working:"
echo "- Open Policy Studio"
echo "- Create a new policy"
echo "- Search for 'Invoke Lambda Function' in the filter palette"
echo "- Configure the filter with the required parameters" 