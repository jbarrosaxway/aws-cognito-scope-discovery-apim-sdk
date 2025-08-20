# Script to configure the Policy Studio project path
# Author: Assistant
# Date: $(Get-Date)

Write-Host "=== Policy Studio Project Configuration ===" -ForegroundColor Green
Write-Host ""

# Request project path
$defaultPath = "C:\Users\jbarros\apiprojects\POC-CUSTOM-FILTER"
Write-Host "Default path: $defaultPath" -ForegroundColor Yellow
Write-Host ""

$projectPath = Read-Host "Enter your Policy Studio project path (or press Enter to use the default)"

if ([string]::IsNullOrWhiteSpace($projectPath)) {
    $projectPath = $defaultPath
}

Write-Host ""
Write-Host "Selected path: $projectPath" -ForegroundColor Cyan

# Check if the directory exists
if (Test-Path $projectPath) {
    Write-Host "✅ Directory found!" -ForegroundColor Green
} else {
    Write-Host "❌ Directory not found!" -ForegroundColor Red
    Write-Host "Do you want to create the directory? (Y/N)" -ForegroundColor Yellow
    $createDir = Read-Host
    
    if ($createDir -eq "Y" -or $createDir -eq "y") {
        try {
            New-Item -ItemType Directory -Path $projectPath -Force | Out-Null
            Write-Host "✅ Directory created successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Error creating directory: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 1
    }
}

# Update scripts with the new path
$scripts = @("install-filter-windows.ps1", "install-filter-windows.cmd")

foreach ($script in $scripts) {
    if (Test-Path $script) {
        Write-Host "Updating $script..." -ForegroundColor Cyan
        
        if ($script -eq "install-filter-windows.ps1") {
            $content = Get-Content $script -Raw
            $content = $content -replace '\$POLICY_STUDIO_PROJECT = ".*?"', "`$POLICY_STUDIO_PROJECT = `"$projectPath`""
            Set-Content $script $content -Encoding UTF8
        } else {
            $content = Get-Content $script -Raw
            $content = $content -replace 'set POLICY_STUDIO_PROJECT=.*?', "set POLICY_STUDIO_PROJECT=$projectPath"
            Set-Content $script $content -Encoding UTF8
        }
        
        Write-Host "✅ $script updated!" -ForegroundColor Green
    } else {
        Write-Host "⚠️ $script not found" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Configuration Completed ===" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next steps:" -ForegroundColor Yellow
Write-Host "1. Run the installation script:" -ForegroundColor White
Write-Host "   PowerShell: .\install-filter-windows.ps1" -ForegroundColor Gray
Write-Host "   CMD: install-filter-windows.cmd" -ForegroundColor Gray
Write-Host "2. Open the project in Policy Studio" -ForegroundColor White
Write-Host "3. Configure AWS SDK JARs if needed" -ForegroundColor White
Write-Host ""
Write-Host "💡 Tip: The scripts are now configured for the project: $projectPath" -ForegroundColor Cyan 