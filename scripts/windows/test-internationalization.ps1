# Test script to verify the functionality of appending content to Internationalization Default.yaml
# Author: Assistant
# Date: $(Get-Date)

Write-Host "=== Internationalization Default.yaml Functionality Test ===" -ForegroundColor Green
Write-Host ""

# Test settings
$testDir = ".\test-internationalization"
$sourceFile = "src\main\resources\yaml\System\Internationalization Default.yaml"
$destFile = "$testDir\Internationalization Default.yaml"

# Create test directory
if (Test-Path $testDir) {
    Remove-Item $testDir -Recurse -Force
}
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

Write-Host "📁 Test directory created: $testDir" -ForegroundColor Cyan

# Function to append content to the end of the file
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

# Test 1: Create new file
Write-Host ""
Write-Host "🧪 Test 1: Create new file" -ForegroundColor Yellow
$success1 = Append-InternationalizationContent -SourceFile $sourceFile -DestFile $destFile

if ($success1) {
    Write-Host "✅ Test 1 passed!" -ForegroundColor Green
    Write-Host "📄 Content of created file:" -ForegroundColor Cyan
    Get-Content $destFile | Write-Host -ForegroundColor Gray
} else {
    Write-Host "❌ Test 1 failed!" -ForegroundColor Red
}

# Test 2: Append content to existing file
Write-Host ""
Write-Host "🧪 Test 2: Append content to existing file" -ForegroundColor Yellow

# Create an existing file with content
$existingContent = @"
- type: ExistingFilter
  fields:
    type: TestFilter
  logging:
    fatal: "Existing error message"
    failure: "Existing failure message"
    success: "Existing success message"
"@

Set-Content -Path $destFile -Value $existingContent -Force
Write-Host "📄 Existing file created with content:" -ForegroundColor Cyan
Get-Content $destFile | Write-Host -ForegroundColor Gray

# Append new content
$success2 = Append-InternationalizationContent -SourceFile $sourceFile -DestFile $destFile

if ($success2) {
    Write-Host "✅ Test 2 passed!" -ForegroundColor Green
    Write-Host "📄 Final content of the file:" -ForegroundColor Cyan
    Get-Content $destFile | Write-Host -ForegroundColor Gray
} else {
    Write-Host "❌ Test 2 failed!" -ForegroundColor Red
}

# Cleanup
Write-Host ""
Write-Host "🧹 Cleaning up test files..." -ForegroundColor Yellow
Remove-Item $testDir -Recurse -Force
Write-Host "✅ Cleanup completed!" -ForegroundColor Green

Write-Host ""
Write-Host "=== Test Completed ===" -ForegroundColor Green
if ($success1 -and $success2) {
    Write-Host "✅ All tests passed! The functionality is working correctly." -ForegroundColor Green
} else {
    Write-Host "❌ Some tests failed. Check the errors above." -ForegroundColor Red
} 