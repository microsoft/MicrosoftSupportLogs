function Invoke-AutoUpdater {
    [CmdletBinding()]
    param(
        # The GitHub API URL to fetch the latest release information
        [string]$RepoURL = 'https://api.github.com/repos/microsoft/MicrosoftSupportLogs/releases/latest',
        # The name of the script file to update
        [string]$ScriptName = 'Generate-Microsoft-Support-Logs*.ps1',
        # The pattern to match the asset in the release assets
        [string]$AssetPattern = 'Generate-Microsoft-Support-Logs.zip*'
    )
    BEGIN {
        # Function to generate a timestamp for log messages
        Function Invoke-TimeStamp {
            $TimeStamp = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
            return "$TimeStamp - "
        }
        # Function to write messages to the console with optional color and newline control
        function Write-Console {
            param (
                [Parameter(Position = 1)]
                [string]$Text,                   # The text to output
                [Parameter(Position = 2)]
                $ForegroundColor,                # The color of the text
                [Parameter(Position = 3)]
                [switch]$NoNewLine               # Switch to suppress the newline
            )
            # Check if the environment is interactive (e.g., PowerShell console)
            if ([Environment]::UserInteractive) {
                # If a foreground color is specified, use it
                if ($ForegroundColor) {
                    Write-Host $Text -ForegroundColor $ForegroundColor -NoNewLine:$NoNewLine
                } else {
                    Write-Host $Text -NoNewLine:$NoNewLine
                }
            } else {
                # If not interactive (e.g., running as a script), output plain text
                Write-Output $Text
            }
        }
        # Function to display version status messages with customizable colors
        Function Show-VersionStatus {
            param (
                [string]$Status,                         # The status title (e.g., "UP TO DATE")
                [string]$Message,                        # The message content
                [ConsoleColor]$HeaderColor = 'White',    # Color for the header and borders
                [ConsoleColor]$ContentColor = 'White'    # Color for the message content
            )
            Write-Host
            $lineLength = 60                             # Length of the border lines
            $border = "=" * $lineLength                  # Create a border line
            # Center the status text within the borders
            $paddedStatus = $Status.PadLeft(([int]($lineLength / 2) + [int]($Status.Length / 2))).PadRight($lineLength)
            # Display the formatted status message with specified colors
            Write-Host $border -ForegroundColor $HeaderColor
            Write-Host $paddedStatus -ForegroundColor $HeaderColor
            Write-Host $border -ForegroundColor $HeaderColor
            Write-Host $Message -ForegroundColor $ContentColor
            Write-Host $border -ForegroundColor $HeaderColor
            Write-Host
        }
    }
    PROCESS {
        try {
            # Attempt to retrieve the latest release information from the GitHub repository
            $githubLatestRelease = (Invoke-WebRequest -ErrorAction Stop -Uri $RepoURL).Content | ConvertFrom-Json
        } catch {
            # If unable to access the repository URL, display an error message and exit
            Write-Console "$(Invoke-TimeStamp)Unable to access the website: " -NoNewLine
            Write-Console $RepoURL -ForegroundColor Red
            Start-Sleep 8
            break
        }
        # Extract the latest release tag name (e.g., "v1.2.3")
        $latestRelease = $githubLatestRelease.tag_name
        # Remove leading 'v' from the latest release version
        $latestReleaseVersion = $latestRelease.Replace('v', '')

        try {
            # Determine the script directory and attempt to find the local script file
            if ($PSScriptRoot) {
                $content = Get-ChildItem "$PSScriptRoot\$ScriptName*" -ErrorAction Stop
            } else {
                $content = Get-ChildItem ".\$ScriptName*" -ErrorAction Stop
            }
            $scriptPath = $content[0].FullName              # Get the full path of the script
            $scriptContent = Get-Content $scriptPath -ErrorAction Stop   # Read the script content
        } catch {
            # If the script is not found locally, prompt the user to download it
            Write-Warning "$(Invoke-TimeStamp)Unable to access the $ScriptName or $ScriptName* file ($pwd). Make sure you are running this in the script directory!"
            do {
                # Prompt the user to attempt downloading the latest release
                $answer = Read-Host "$(Invoke-TimeStamp)Attempt to download latest release from the internet? (Y/N)"
            } until ($answer -eq 'y' -or $answer -eq 'n')   # Repeat until a valid response is given
            if ($answer -eq 'n') {
                # If the user chooses not to download, exit the script
                Write-Console "$(Invoke-TimeStamp)Stopping script"
                break
            } else {
                # Proceed to download the latest release asset
                Write-Console "$(Invoke-TimeStamp)Latest Release: " -NoNewLine
                Write-Console $latestReleaseVersion -ForegroundColor Green
                Write-Console "$(Invoke-TimeStamp)Finding asset matching pattern: $AssetPattern"

                # Search for the asset in the release assets that matches the specified pattern
                $githubAsset = $githubLatestRelease.Assets | Where-Object { $_.Name -like $AssetPattern } | Select-Object -First 1

                if ($null -eq $githubAsset) {
                    # If no matching asset is found, display an error and exit
                    Write-Console "$(Invoke-TimeStamp)No suitable asset found in the release." -ForegroundColor Red
                    break
                }

                # Determine the file extension of the asset (e.g., ".zip", ".ps1")
                $assetExtension = [System.IO.Path]::GetExtension($githubAsset.Name)
                $filePath = Join-Path $pwd $githubAsset.Name   # Construct the full path for the downloaded asset

                # Download the asset file from the release
                Write-Console "$(Invoke-TimeStamp)Downloading asset: $($githubAsset.Name) -> $filePath"
                Invoke-WebRequest $githubAsset.browser_download_url -OutFile $filePath

                # Handle the asset based on its file extension
                if ($assetExtension -eq '.zip') {
                    # If the asset is a ZIP file, extract its contents
                    Write-Console "$(Invoke-TimeStamp)Expanding zip archive: $($githubAsset.Name)"
                    Expand-Archive -LiteralPath $filePath -DestinationPath $pwd -Force
                    # Remove the ZIP file after extraction
                    Write-Console "$(Invoke-TimeStamp)Cleaning up zip release..."
                    Remove-Item -LiteralPath $filePath -Force | Out-Null
                } elseif ($assetExtension -eq '.ps1') {
                    # If the asset is a PowerShell script, inform the user
                    Write-Console "$(Invoke-TimeStamp)Downloaded PowerShell script: $($githubAsset.Name)"
                    # No extraction needed for .ps1 files
                } else {
                    # If the asset type is unknown, display an error and exit
                    Write-Console "$(Invoke-TimeStamp)Unknown asset type: $($githubAsset.Name)" -ForegroundColor Red
                    break
                }
            }
        }
        # Proceed if the script was found or successfully downloaded
        if (!$answer) {
            # Attempt to extract the version number from the script content
			$versionLine = $scriptContent | Select-String -Pattern '(Version: \d+(\.\d+)*|DevelopmentVersion)' | Select-Object -First 1
			if ($versionLine)
			{
				if ($versionLine -match "DevelopmentVersion")
				{
					$scriptVersion = "999.0.0" # Set a high version to trigger development build message
				}
				else
				{
					# Extract the version number from the matched line
					$scriptVersion = ($versionLine -split "Version: ")[1].Trim().Replace("v", "")
				}
			}
			else
			{
				# If no version is found, default to "0.0.0"
				$scriptVersion = "0.0.0"
			}
			
			# Compare the local script version with the latest release version
            if ([version]$scriptVersion -gt [version]$latestReleaseVersion) {
                # If the local version is newer than the latest release, it's a development build
                $status = "DEVELOPMENT BUILD"
				$message = "You are currently on a development build of $($content.Name) last modified on $(($scriptContent | Select-String -Pattern 'Last Modified: (.*)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1).Trim())"
				
                # Display the status message with yellow header color
                Show-VersionStatus -Status $status -Message $message -HeaderColor Yellow -ContentColor White
            } elseif ([version]$scriptVersion -lt [version]$latestReleaseVersion) {
                # If the local version is older, an update is available
                $status = "UPDATE AVAILABLE"
                $message = "Current Script Version: $scriptVersion`nLatest Release Version: $latestReleaseVersion"
                # Display the status message with red header color
                Show-VersionStatus -Status $status -Message $message -HeaderColor Red -ContentColor White

                # Remove old script files before downloading the new version
                Write-Console "$(Invoke-TimeStamp)Removing old script files to replace with newer versions."
                Get-ChildItem -Path .\ -Include $ScriptName*, "$($ScriptName)-v*.*.*", Queries | Remove-Item -Recurse -Force

                # Find and download the latest asset matching the pattern
                Write-Console "$(Invoke-TimeStamp)Finding asset matching pattern: $AssetPattern"

                $githubAsset = $githubLatestRelease.Assets | Where-Object { $_.Name -like $AssetPattern } | Select-Object -First 1

                if ($null -eq $githubAsset) {
                    # If no matching asset is found, display an error and exit
                    Write-Console "$(Invoke-TimeStamp)No suitable asset found in the release." -ForegroundColor Red
                    break
                }

                # Determine the file extension and construct the download path
                $assetExtension = [System.IO.Path]::GetExtension($githubAsset.Name)
                $filePath = Join-Path $pwd $githubAsset.Name

                # Download the asset from the release
                Write-Console "$(Invoke-TimeStamp)Downloading asset: $($githubAsset.Name) -> $filePath"
                Invoke-WebRequest $githubAsset.browser_download_url -OutFile $filePath

                # Handle the downloaded asset based on its type
                if ($assetExtension -eq '.zip') {
                    # If it's a ZIP file, extract it
                    Write-Console "$(Invoke-TimeStamp)Expanding zip archive: $($githubAsset.Name)"
                    Expand-Archive -LiteralPath $filePath -DestinationPath $pwd -Force
                    # Remove the ZIP file after extraction
                    Write-Console "$(Invoke-TimeStamp)Cleaning up zip release..."
                    Remove-Item -LiteralPath $filePath -Force | Out-Null
                } elseif ($assetExtension -eq '.ps1') {
                    # If it's a PowerShell script, inform the user
                    Write-Console "$(Invoke-TimeStamp)Downloaded PowerShell script: $($githubAsset.Name)"
                    # No extraction needed
                } else {
                    # If the asset type is unrecognized, display an error and exit
                    Write-Console "$(Invoke-TimeStamp)Unknown asset type: $($githubAsset.Name)" -ForegroundColor Red
                    break
                }
            } else {
                # If the local version matches the latest release, inform the user
                $status = "UP TO DATE"
                $message = "You are currently on the latest version of $($content.Name): $latestReleaseVersion"
                # Display the status message with green header color
                Show-VersionStatus -Status $status -Message $message -HeaderColor Green -ContentColor White
            }
        }
    }
    END {
        # Final message indicating the script has completed its execution
        Write-Console "$(Invoke-TimeStamp)Script completed!"
        Start-Sleep -Seconds 8
    }
}
# Invoke the auto-updater function to check for updates and handle accordingly
Invoke-AutoUpdater