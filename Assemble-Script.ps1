<#
Information
	Author: Blake Drumm (blakedrumm@microsoft.com)
	This script takes all the functions from .\Functions\* and combines them into the main powershell script. Allowing the Data Collector to run with just one PS1 file and the SQL Queries folder.
	
	This has to be in the same folder as the Generate-Microsoft-Support-Logs.ps1 file / Functions Folder to work.

	For this to work the functions names have to be on the first lines of each file in the functions folder.
#>
$ScriptPath = (Get-Location).Path
$mainscript = Get-Content .\Generate-Microsoft-Support-Logs.ps1

$ScriptFunctions = Get-ChildItem .\Functions | Where-Object{ $_ -like '*.ps1' } | Select-Object FullName -ExpandProperty FullName
# Main Script Functions
foreach ($script in $ScriptFunctions)
{
	$filename = $null
	$functionpath = $null
	$innerfunction = $null
	$innerfunctionName = $null
	$filename = $script | Split-Path -Leaf
	$functionpath = '. $ScriptPath`\Functions\' + $filename
	$functionpathwithQuotes = ". `"`$ScriptPath`\Functions\$filename`""
	$innerfunction = Get-Content $script | Out-String
	foreach ($f in $innerfunction)
	{
		$mainscript = ($mainscript).Replace("$functionpath", $f)
		$mainscript = ($mainscript).Replace("$functionpathwithQuotes", $f)
	}
}
# Remove commands in script
$mainscript = ($mainscript).Replace('	# Development Mode Unblock (Optional) [DO NOT EDIT THE BELOW LINE]', $null)
$mainscript = ($mainscript).Replace('	Write-Console -MessageSegments (@(@{ Text = "[" }, @{ Text = "DEV"; ForegroundColor = "Cyan" }, @{ Text = "] " }, @{ Text = "Attempting to run the following command to unblock the PowerShell Scripts under the current folder:`nGet-ChildItem `"$ScriptPath`" -Recurse | Unblock-File"; ForegroundColor = "Gray" })); Get-ChildItem "$ScriptPath" -Recurse | Unblock-File | Out-Null', $null)
$mainscript = ($mainscript).Replace('#Push-Location $outputFolder', 'Push-Location $outputFolder')

# Auto Updater Function
$mainscript = ($mainscript).Replace('. $ScriptPath`\Start-ScriptAutoUpdater.ps1', (Get-Content .\Start-ScriptAutoUpdater.ps1 | Out-String))
# Replace any $global: variables with $script: variables
$mainscript = ($mainscript).Replace('$global:', '$script:')
# Get version
$version = Get-Item .\v* | Select-Object Name -ExpandProperty Name

# Replace the version in script with actual version
$rawVersion = $version.Replace('v', '')
$mainscript = $mainscript.Replace('DevelopmentVersion', $rawVersion)

$mainscript | Out-File ".\Generate-Microsoft-Support-Logs-$version.ps1" -Force