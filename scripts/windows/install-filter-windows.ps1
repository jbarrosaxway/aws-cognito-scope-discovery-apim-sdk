# Invoke Lambda Function installation script for Axway API Gateway (Windows)
# Author: Assistant
# Date: $(Get-Date)

# Settings
$POLICY_STUDIO_PROJECT = "C:\Users\jbarros\apiprojects\POC-CUSTOM-FILTER"
$PROJECT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$YAML_SOURCE_DIR = Join-Path $PROJECT_DIR "src\main\resources\yaml"

Write-Host "=== Invoke Lambda Function Installation for Policy Studio (Windows) ===" -ForegroundColor Green
Write-Host "Policy Studio project: $POLICY_STUDIO_PROJECT" -ForegroundColor Yellow
Write-Host "Project directory: $PROJECT_DIR" -ForegroundColor Yellow
Write-Host "YAML source directory: $YAML_SOURCE_DIR" -ForegroundColor Yellow
Write-Host ""

# Check if Policy Studio project directory exists
if (-not (Test-Path $POLICY_STUDIO_PROJECT)) {
    Write-Host "❌ Error: Policy Studio project not found: $POLICY_STUDIO_PROJECT" -ForegroundColor Red
    Write-Host "Adjust the `$POLICY_STUDIO_PROJECT variable in the script if needed" -ForegroundColor Yellow
    exit 1
}

# Check if YAML source directory exists
if (-not (Test-Path $YAML_SOURCE_DIR)) {
    Write-Host "❌ Error: YAML source directory not found: $YAML_SOURCE_DIR" -ForegroundColor Red
    Write-Host "Build the project first" -ForegroundColor Yellow
    exit 1
}

# Function to copy YAML files
function Copy-YamlFiles {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [string]$Description
    )
    
    Write-Host "📁 Copying $Description..." -ForegroundColor Cyan
    
    # Create destination directory if it does not exist
    if (-not (Test-Path $DestPath)) {
        New-Item -ItemType Directory -Path $DestPath -Force | Out-Null
        Write-Host "  Directory created: $DestPath" -ForegroundColor Gray
    }
    
    # Copy files
    try {
        Copy-Item -Path "$SourcePath\*" -Destination $DestPath -Recurse -Force
        Write-Host "  ✅ $Description copied successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Error copying $Description: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    return $true
}

# Function to append content to the end of Internationalization Default.yaml
function Append-InternationalizationContent {
    param(
        [string]$SourceFile,
        [string]$DestFile
    )
    
    Write-Host "📝 Adding content to Internationalization Default.yaml..." -ForegroundColor Cyan
    
    try {
        # Read content from source file
        $sourceContent = Get-Content $SourceFile -Raw
        
        # Check if destination file exists
        if (Test-Path $DestFile) {
            # Append content to the end of the existing file
            Add-Content -Path $DestFile -Value "`n$sourceContent"
            Write-Host "  ✅ Content added to the end of the existing file" -ForegroundColor Green
        } else {
            # Create new file if it does not exist
            Copy-Item -Path $SourceFile -Destination $DestFile -Force
            Write-Host "  ✅ File created with content" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Host "  ❌ Error adding content: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# 1. Copy InvokeLambdaFunctionFilter.yaml
$sourceFilter = Join-Path $YAML_SOURCE_DIR "META-INF\types\Entity\Filter\AWSFilter"
$destFilter = Join-Path $POLICY_STUDIO_PROJECT "META-INF\types\Entity\Filter\AWSFilter"

$filterSuccess = Copy-YamlFiles -SourcePath $sourceFilter -DestPath $destFilter -Description "InvokeLambdaFunctionFilter.yaml"

# 2. Add content to Internationalization Default.yaml
$sourceSystemFile = Join-Path $YAML_SOURCE_DIR "System\Internationalization Default.yaml"
$destSystemFile = Join-Path $POLICY_STUDIO_PROJECT "System\Internationalization Default.yaml"

# Create System directory if it does not exist
$destSystemDir = Join-Path $POLICY_STUDIO_PROJECT "System"
if (-not (Test-Path $destSystemDir)) {
    New-Item -ItemType Directory -Path $destSystemDir -Force | Out-Null
    Write-Host "  Directory created: $destSystemDir" -ForegroundColor Gray
}

$systemSuccess = Append-InternationalizationContent -SourceFile $sourceSystemFile -DestFile $destSystemFile

# Check if both operations were successful
if ($filterSuccess -and $systemSuccess) {
    Write-Host ""
    Write-Host "=== Installation Completed ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "📝 Next steps:" -ForegroundColor Yellow
    Write-Host "1. Open the project in Policy Studio" -ForegroundColor White
    Write-Host "2. Go to Window > Preferences > Runtime Dependencies" -ForegroundColor White
    Write-Host "3. Add AWS SDK JARs if needed:" -ForegroundColor White
    Write-Host "   - aws-java-sdk-lambda-1.12.314.jar" -ForegroundColor Gray
    Write-Host "   - aws-java-sdk-core-1.12.314.jar" -ForegroundColor Gray
    Write-Host "4. Restart Policy Studio with the -clean option" -ForegroundColor White
    Write-Host "5. The 'Invoke Lambda Function' will be available in the filter palette" -ForegroundColor White
    Write-Host ""
    Write-Host "🔧 To check if the filter is working:" -ForegroundColor Yellow
    Write-Host "- Open Policy Studio" -ForegroundColor White
    Write-Host "- Create a new policy" -ForegroundColor White
    Write-Host "- Search for 'Invoke Lambda Function' in the filter palette" -ForegroundColor White
    Write-Host "- Configure the filter with the required parameters" -ForegroundColor White
    Write-Host ""
    Write-Host "📋 Copied files:" -ForegroundColor Yellow
    Write-Host "- $destFilter\InvokeLambdaFunctionFilter.yaml" -ForegroundColor Gray
    Write-Host "- $destSystem\Internationalization Default.yaml" -ForegroundColor Gray
    Write-Host ""
    Write-Host "💡 Tip: Adjust the `$POLICY_STUDIO_PROJECT variable in the script if your project is in another location" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "❌ Error during installation. Check the messages above." -ForegroundColor Red
    exit 1
} 