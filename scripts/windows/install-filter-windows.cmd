@echo off
REM Invoke Lambda Function installation script for Axway API Gateway (Windows CMD)
REM Author: Assistant
REM Date: %date% %time%

REM Settings
set POLICY_STUDIO_PROJECT=C:\Users\jbarros\apiprojects\POC-CUSTOM-FILTER
set PROJECT_DIR=%~dp0
set YAML_SOURCE_DIR=%PROJECT_DIR%src\main\resources\yaml

echo === Invoke Lambda Function Installation for Policy Studio (Windows) ===
echo Policy Studio project: %POLICY_STUDIO_PROJECT%
echo Project directory: %PROJECT_DIR%
echo YAML source directory: %YAML_SOURCE_DIR%
echo.

REM Check if Policy Studio project directory exists
if not exist "%POLICY_STUDIO_PROJECT%" (
    echo  [31mError: Policy Studio project not found: %POLICY_STUDIO_PROJECT% [0m
    echo Adjust the POLICY_STUDIO_PROJECT variable in the script if needed
    pause
    exit /b 1
)

REM Check if YAML source directory exists
if not exist "%YAML_SOURCE_DIR%" (
    echo  [31mError: YAML source directory not found: %YAML_SOURCE_DIR% [0m
    echo Build the project first
    pause
    exit /b 1
)

REM Function to copy YAML files
:CopyYamlFiles
set SourcePath=%~1
set DestPath=%~2
set Description=%~3

echo  [36mCopying %Description%... [0m

REM Create destination directory if it does not exist
if not exist "%DestPath%" (
    mkdir "%DestPath%" 2>nul
    echo   Directory created: %DestPath%
)

REM Copy files
xcopy "%SourcePath%\*" "%DestPath%\" /E /Y /Q >nul 2>&1
if %errorlevel% equ 0 (
    echo    [32m%Description% copied successfully [0m
    set /a success=1
) else (
    echo    [31mError copying %Description% [0m
    set /a success=0
)
goto :eof

REM Function to append content to the end of Internationalization Default.yaml
:AppendInternationalizationContent
set SourceFile=%~1
set DestFile=%~2

echo  [36mAdding content to Internationalization Default.yaml... [0m

REM Check if destination file exists
if exist "%DestFile%" (
    REM Append content to the end of the existing file
    echo. >> "%DestFile%"
    type "%SourceFile%" >> "%DestFile%"
    echo    [32mContent added to the end of the existing file [0m
) else (
    REM Create new file if it does not exist
    copy "%SourceFile%" "%DestFile%" >nul 2>&1
    echo    [32mFile created with content [0m
)

if %errorlevel% equ 0 (
    set /a success=1
) else (
    echo    [31mError adding content [0m
    set /a success=0
)
goto :eof

REM 1. Copy InvokeLambdaFunctionFilter.yaml
set sourceFilter=%YAML_SOURCE_DIR%\META-INF\types\Entity\Filter\AWSFilter
set destFilter=%POLICY_STUDIO_PROJECT%\META-INF\types\Entity\Filter\AWSFilter

call :CopyYamlFiles "%sourceFilter%" "%destFilter%" "InvokeLambdaFunctionFilter.yaml"
set filterSuccess=%success%

REM 2. Add content to Internationalization Default.yaml
set sourceSystemFile=%YAML_SOURCE_DIR%\System\Internationalization Default.yaml
set destSystemFile=%POLICY_STUDIO_PROJECT%\System\Internationalization Default.yaml

REM Create System directory if it does not exist
set destSystemDir=%POLICY_STUDIO_PROJECT%\System
if not exist "%destSystemDir%" (
    mkdir "%destSystemDir%" 2>nul
    echo   Directory created: %destSystemDir%
)

call :AppendInternationalizationContent "%sourceSystemFile%" "%destSystemFile%"
set systemSuccess=%success%

REM Check if both operations were successful
if %filterSuccess% equ 1 if %systemSuccess% equ 1 (
    echo.
    echo === Installation Completed ===
    echo.
    echo  [33mNext steps: [0m
    echo 1. Open the project in Policy Studio
    echo 2. In Policy Studio, go to Window ^> Preferences ^> Runtime Dependencies
    echo 3. Add AWS SDK JARs if needed:
    echo    - aws-java-sdk-lambda-1.12.314.jar
    echo    - aws-java-sdk-core-1.12.314.jar
    echo 4. Restart Policy Studio with the -clean option
    echo 5. The 'Invoke Lambda Function' will be available in the filter palette
    echo.
    echo  [36mTo check if the filter is working: [0m
    echo - Open Policy Studio
    echo - Create a new policy
    echo - Search for 'Invoke Lambda Function' in the filter palette
    echo - Configure the filter with the required parameters
    echo.
    echo  [33mCopied files: [0m
    echo - %destFilter%\InvokeLambdaFunctionFilter.yaml
    echo - %destSystem%\Internationalization Default.yaml
    echo.
    echo  [36mTip: Adjust the POLICY_STUDIO_PROJECT variable in the script if your project is in another location [0m
) else (
    echo.
    echo  [31mError during installation. Check the messages above. [0m
    pause
    exit /b 1
)

pause 