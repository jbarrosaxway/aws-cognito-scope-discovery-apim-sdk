# AWS Cognito Scope Discovery Integration for Axway API Gateway

This project provides integration with AWS Cognito through custom filters for Axway API Gateway, supporting dynamic scope discovery without fixed mappings.

## 🚀 Quick Start Guide

### Installation from GitHub Release

1. **Download the latest release ZIP**
2. **Extract and copy the files:**
   ```bash
   # Copy main JAR
   cp aws-cognito-scope-discovery-apim-sdk-*.jar /opt/Axway/apigateway/groups/group-2/instance-1/ext/lib/
   
   # Copy AWS SDK dependency
   cp dependencies/external-aws-java-sdk-cognitoidp-*.jar /opt/Axway/apigateway/groups/group-2/instance-1/ext/lib/
   ```

3. **Restart the gateway:**
   - Use the appropriate method for your installation (service, script, etc.)

4. **Add to Policy Studio:**
   - Open Policy Studio
   - Go to **Window > Preferences > Runtime Dependencies**
   - Add the JARs to the classpath
   - Restart Policy Studio with `-clean`

5. **Use the filter:**
   - Search for **"Cognito Scope Discovery"** in the palette
   - Configure the required parameters
   - Test the integration

---

## API Management Version Compatibility

This artifact has been successfully tested with the following versions:
- **Axway API Gateway 7.7.0.20240830** ✅

## Overview

The project offers AWS Cognito integration for dynamic scope discovery:

### 1. Java Filter (Recommended)
- Graphical interface in Policy Studio
- Configuration via visual parameters
- Native gateway performance
- Automated build
- Dynamic scope discovery from Cognito
- Intelligent caching system

## 📦 GitHub Releases

### **Automatic Downloads**

Releases are automatically created on GitHub and include:

#### **Files Available in Each Release:**
- **Main JAR** - `aws-cognito-scope-discovery-apim-sdk-*.jar` (built for multiple Axway versions)
- **External Dependencies** - `dependencies/` folder with AWS SDK JARs
- **Policy Studio Resources** - `src/main/resources/fed/` and `src/main/resources/yaml/`
- **Gradle Wrapper** - `gradlew`, `gradlew.bat` and `gradle/` folder
- **Gradle Configuration** - `build.gradle` with installation tasks
- **Linux Script** - `install-linux.sh` for automated installation

#### **Installation from Release:**

**Windows (Recommended):**
```bash
# Extract the release ZIP
# Navigate to the extracted folder
# Run the Gradle task:
.\gradlew "-Dproject.path=C:\Users\jbarros\apiprojects\my-axway-project" installWindowsToProject
```

**Linux:**
```bash
# Extract the release ZIP
# Run the installation script:
./install-linux.sh
```

### **Supported Versions:**

Supported versions are defined in **[📋 axway-versions.json](axway-versions.json)**:

| Version | Description |
|---------|-------------|
| **7.7.0.20240830** | Stable August 2024 version - AWS SDK detected automatically |
| **7.7.0.20250530** | Stable May 2025 version - AWS SDK detected automatically |

**Default version:** `7.7.0.20240830`

---

## Build and Installation

### 🔧 Dynamic Configuration

The project supports **dynamic configuration** of the Axway API Gateway path:

```bash
# Default configuration
./gradlew clean build installLinux

# Custom configuration
./gradlew -Daxway.base=/opt/axway/Axway-7.7.0.20210830 clean build installLinux

# Check current configuration
./gradlew setAxwayPath
```

### Linux
```bash
# Build the JAR (Linux only)
./gradlew buildJarLinux

# Automated build and installation
./gradlew clean build installLinux

# With custom path
./gradlew -Daxway.base=/path/to/axway clean build installLinux
```

### Windows
```bash
# Install only YAML files in Policy Studio project
./gradlew installWindows

# Install in specific project (with path)
./gradlew "-Dproject.path=C:\Users\jbarros\apiprojects\my-axway-project" installWindowsToProject

# Interactive installation (if path not specified)
./gradlew installWindowsToProject
```

### 🐳 **Docker**

#### **Build with Docker**

This project uses Docker images for automated build, configured in **[📋 axway-versions.json](axway-versions.json)**.

**Image contents:**
- Axway API Gateway (specific version)
- Java 11 OpenJDK
- AWS SDK for Java 1.12.314
- Gradle for build
- All required dependencies

#### **Build using Docker**

```bash
# Build the JAR using the published image (default version)
./scripts/build-with-docker-image.sh

# Or manually:
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/build:/workspace/build" \
  -w /workspace \
  <docker-image> \
  bash -c "
    export JAVA_HOME=/opt/java/openjdk-11
    export PATH=\$JAVA_HOME/bin:\$PATH
    gradle clean build
  "
```

> 💡 **Tip**: GitHub Actions uses the published image `axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0`.

#### **Test Published Image**

```bash
# Test the published image

# Or manually:
docker pull axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0
docker run --rm axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0 java -version
docker run --rm axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0 ls -la /opt/Axway/
```

> ⚠️ **Note**: This image is **for build only**, not for application runtime.

#### **JAR Structure in the Image**

The image includes the following JARs organized:

```
/opt/Axway/apigateway/lib/
├── aws-java-sdk-cognitoidp-*.jar          # AWS Cognito SDK
├── aws-java-sdk-core-*.jar                # AWS Core SDK
└── jackson-*.jar                          # Jackson JSON library
```

#### **Using the Image for Build**

The image `axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0` is **for build only**, not for runtime. It contains all Axway API Gateway libraries needed to compile the project:

```bash
# Build using the image (libraries only)
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/build:/workspace/build" \
  -w /workspace \
  axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0 \
  bash -c "
    export JAVA_HOME=/opt/java/openjdk-11
    export PATH=\$JAVA_HOME/bin:\$PATH
    gradle clean build
  "
```

#### **Image Specifications:**
- **Base**: Axway API Gateway 7.7.0.20240830-4-BN0145-ubi9
- **Java**: OpenJDK 11.0.27
- **Libraries**: All Axway API Gateway libs available
- **Usage**: Build only, not for application runtime

#### **GitHub Actions**

The project uses the image for automated build:

- **Continuous Build**: `.github/workflows/build-jar.yml`
- **Release**: `.github/workflows/release.yml`
- **Image**: `axwayjbarros/aws-cognito-scope-discovery-apim-sdk:1.0.0`

> 📖 **Docker**: Docker documentation is integrated in this README section.

### ⚠️ **Important: JAR Build**

**The JAR build must be done on Linux** due to Axway API Gateway dependencies. For Windows:

1. **Build on Linux:**
   ```bash
   ./gradlew buildJarLinux
   ```

2. **Copy JAR to Windows:**
   ```bash
   # Copy the file: build/libs/aws-cognito-scope-discovery-apim-sdk-1.0.0.jar
   # To the Windows environment
   ```

3. **Install YAML on Windows:**
   ```bash
   ./gradlew installWindows
   ```

### 🔄 **Linux vs Windows Process**

| Linux | Windows |
|-------|---------|
| ✅ JAR build | ❌ JAR build |
| ✅ Full installation | ✅ YAML installation |
| ✅ Native dependencies | ⚠️ External JARs |
| ✅ Automatic configuration | ⚠️ Manual configuration |

**Linux**: Full process (JAR + YAML + installation)  
**Windows**: YAML only (JAR must be built on Linux)

### Useful Commands
```bash
# List all available tasks
./gradlew showTasks

# Show AWS SDK JAR links
./gradlew showAwsJars

# Check Axway configuration
./gradlew setAxwayPath

# Build only
./gradlew clean build
```

## 📚 Documentation

This project has complete documentation organized by topic:

### 🚀 **Installation Guides**
- **[📋 Windows Installation Guide](docs/WINDOWS_INSTALLATION.md)** - Detailed instructions for Windows
- **[🔧 Dynamic Configuration](docs/DYNAMIC_CONFIGURATION.md)** - How to configure Axway paths dynamically

### 🔧 **Development and Build**
- **[🗳️ Release Guide](docs/RELEASE_GUIDE.md)** - How to create releases and versioning
- **[📊 Semantic Versioning](docs/SEMANTIC_VERSIONING.md)** - Automatic versioning system
- **[🤖 Automatic Release System](docs/AUTOMATIC_RELEASE_SYSTEM.md)** - Intelligent analysis and automatic release creation
- **[🔧 Scripts Reference](docs/SCRIPTS_REFERENCE.md)** - Documentation of essential scripts

### 📝 **Technical Documentation**
- **[🔍 Field Updates](docs/FILTER_FIELD_UPDATES.md)** - History of filter field changes
- **[🔐 AWS Authentication Improvements](docs/AWS_AUTHENTICATION_IMPROVEMENTS.md)** - Advanced authentication settings

### 📋 **Documentation Structure**
```
docs/
├── RELEASE_GUIDE.md                    # Release guide
├── SEMANTIC_VERSIONING.md              # Semantic versioning
├── AUTOMATIC_RELEASE_SYSTEM.md         # Automatic release system
├── SCRIPTS_REFERENCE.md                # Scripts reference
└── AWS_COGNITO_DOCUMENTATION.md        # Cognito documentation
```

---

## Manual Installation (Alternative)

### Linux

1. **Automated build and installation:**
   ```bash
   ./gradlew clean build
   ./scripts/linux/install-filter.sh
   ```

2. **Configure Policy Studio:**
   - Open Policy Studio
   - Go to **Window > Preferences > Runtime Dependencies**
   - Add the JAR: `/opt/axway/Axway-7.7.0.20240830/apigateway/groups/group-2/instance-1/ext/lib/aws-cognito-scope-discovery-apim-sdk-1.0.0.jar`
   - Restart Policy Studio with `-clean`

### Windows

1. **Install YAML files (interactive):**
   ```bash
   ./gradlew installWindows
   ```
   Gradle will prompt for the Policy Studio project path.

2. **Install YAML files in a specific project:**
   ```bash
   ./gradlew -Dproject.path=C:\path\to\project installWindowsToProject
   ```

3. **Show AWS SDK JAR links:**
   ```bash
   ./gradlew showAwsJars
   ```

4. **Configure Policy Studio:**
   - Open Policy Studio
   - Go to **Window > Preferences > Runtime Dependencies**
   - Add the JAR: `aws-cognito-scope-discovery-apim-sdk-1.0.0.jar`
   - Restart Policy Studio with `-clean`

## AWS Configuration

### Credentials

#### 1. Credentials File (Recommended)
```ini
# ~/.aws/credentials
[default]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key
aws_session_token = your_session_token  # optional
```

#### 2. Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_SESSION_TOKEN="your_session_token"  # optional
export AWS_DEFAULT_REGION="us-east-1"
```

#### 3. IAM Roles (Recommended for Production)

**For EKS (Kubernetes):**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: axway-api-gateway
spec:
  template:
    spec:
      serviceAccountName: axway-gateway-sa
      containers:
      - name: axway-gateway
        image: axway/api-gateway:latest
        # No environment variables - uses IAM Role automatically
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: axway-gateway-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/axway-cognito-role
```

**For EC2:**
- Attach an IAM Role to the EC2 instance
- The Java filter will automatically detect the credentials

**Advantages:**
- ✅ Maximum security (no static credentials)
- ✅ Automatic credential rotation
- ✅ Auditing via CloudTrail
- ✅ Works with Java filter

## Usage

### Java Filter

**Basic usage:**
1. **Install JARs:**
   - Copy `aws-cognito-scope-discovery-apim-sdk-<version>.jar` to `/opt/Axway/apigateway/groups/group-2/instance-1/ext/lib/`
   - Copy `dependencies/external-aws-java-sdk-cognitoidp-<version>.jar` to the same directory
   - Restart the gateway

2. **Add to Policy Studio:**
   - Go to **Window > Preferences > Runtime Dependencies**
   - Add the JARs to the classpath
   - Restart Policy Studio with `-clean`

3. **Configure filter:**
   - Search for **"Cognito Scope Discovery"** in the palette
   - Configure the required parameters
   - Test the integration

## Project Structure

```
aws-cognito-scope-discovery-apim-sdk/
├── README.md                                # Main documentation
├── docs/                                    # 📚 Project documentation
├── build.gradle                             # Gradle build configuration
├── axway-versions.json                      # Supported Axway versions
├── scripts/                                 # Utility and build scripts
│   ├── build-with-docker-image.sh           # Build JAR with Docker
│   ├── check-release-needed.sh              # Release analysis (CI/CD)
│   ├── version-bump.sh                      # Semantic versioning (CI/CD)
│   ├── install-linux.sh                     # Linux install script
│   ├── linux/
│   │   └── install-filter.sh                # Linux filter install (usado pelo Gradle)
│   └── windows/
│       ├── install-filter-windows.ps1       # Windows PowerShell install
│       ├── install-filter-windows.cmd       # Windows CMD install
│       ├── configurar-projeto-windows.ps1   # Windows project config
│       └── test-internationalization.ps1    # Internationalization test
├── src/
│   └── main/
│       ├── java/                            # Java source code
│       └── resources/
│           ├── fed/
│           │   ├── CognitoScopeDiscoveryDesc.xml
│           │   └── CognitoScopeDiscoveryTypeSet.xml
│           └── yaml/
│               ├── System/
│               │   ├── Internationalization Default.yaml
│               │   └── ... (backups)
│               └── META-INF/
│                   └── types/
│                       └── Entity/
│                           └── Filter/
│                               └── CognitoScopeDiscoveryFilter.yaml
└── build/                                   # Build output (generated)
    └── libs/
        └── aws-cognito-scope-discovery-apim-sdk-<version>.jar
```

## Tests

### Test Status

| Test Type | Java Filter |
|-----------|-------------|
| **Entity Store (YAML)** | ✅ Tested |
| **Entity Store (XML)** | ❌ **Not tested** |

### Next Required Tests

1. **Test Entity Store XML** - Validate compatibility with XML format
2. **Performance Tests** - Evaluate performance with different loads
3. **Concurrency Tests** - Multiple simultaneous invocations

## Troubleshooting

### Common Issues

1. **Filter does not appear in the palette:**
   - Check if the JAR was added to the classpath
   - Restart Policy Studio with `-clean`

2. **AWS credentials error:**
   - Check if credentials are configured
   - Test with `aws sts get-caller-identity`

3. **Cognito client not found error:**
   - Check the client ID and user pool ID
   - Confirm the client exists in AWS Cognito

### Logs

The filter generates detailed logs:
- **Success**: "Success in the Cognito Scope Discovery filter"
- **Failure**: "Failed in the Cognito Scope Discovery filter"
- **Error**: "Error in the Cognito Scope Discovery filter: ${circuit.exception}"

## Security

- Use IAM Roles whenever possible
- Rotate credentials regularly
- Use IAM policies with least privilege
- Monitor access and execution logs
- Consider using AWS Secrets Manager for sensitive credentials

## 🚀 **CI/CD Pipeline**

### **GitHub Actions**

The project includes automated workflows that use Docker for build:

#### **CI (Continuous Integration)**
- **Trigger**: Push to `main`, `develop` or Pull Requests
- **Actions**:
  - ✅ Login to Axway registry (for base image)
  - ✅ Build Docker build image (with Axway + Gradle)
  - ✅ Build JAR inside Docker container
  - ✅ Upload JAR as artifact
  - ✅ JAR tests

#### **Release**
- **Trigger**: Tag push (`v*`)
- **Actions**:
  - ✅ Login to Axway registry
  - ✅ Build Docker build image
  - ✅ Build JAR inside container
  - ✅ Generate changelog
  - ✅ Create GitHub Release
  - ✅ Upload JAR to release
  - ✅ JAR tests

### **Build Flow**

```
1. Login to Axway Registry
   ↓
2. Build Docker image (with Axway + Gradle)
   ↓
3. Run JAR build inside container
   ↓
4. Generate final JAR
   ↓
5. Upload to GitHub Release/Artifacts
```

### **Why use Docker?**

- ✅ Consistent environment: Always the same Axway environment
- ✅ Guaranteed dependencies: Axway + Gradle + Java 11
- ✅ Isolation: Build isolated in container
- ✅ Reproducibility: Always the same result
- ✅ Does not publish image: Only used for build

### **Generated Artifacts**

#### **Main JAR**
```
aws-cognito-scope-discovery-apim-sdk-1.0.0.jar
├── AWS Cognito Scope Discovery Java Filter
├── Policy Studio UI classes
├── AWS SDK dependencies
└── YAML configurations
```

#### **Location**
- **GitHub Releases**: Available for download
- **GitHub Actions Artifacts**: During CI/CD
- **Local**: `build/libs/aws-cognito-scope-discovery-apim-sdk-*.jar`

### How to Use

#### Download the JAR
1. Go to **Releases** on GitHub
2. Download the JAR of the desired version
3. Follow the installation guide

#### Local Build
```bash
# Build the JAR (requires local Axway)
./gradlew buildJarLinux

# Or using the automated Docker build (recommended)
./scripts/build-with-docker-image.sh
```

#### Docker for Development

## Contributing

Please read [Contributing.md](https://github.com/Axway-API-Management-Plus/Common/blob/master/Contributing.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Team

![alt text][Axwaylogo] Axway Team

[Axwaylogo]: https://github.com/Axway-API-Management/Common/blob/master/img/AxwayLogoSmall.png  "Axway logo"

## License
[Apache License 2.0](LICENSE)
