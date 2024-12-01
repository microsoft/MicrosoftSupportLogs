<#
    .SYNOPSIS
        Get-EventLogs
    
    .DESCRIPTION
        This Script Collects Event Log data from Remote Servers and the Local Machine if defined. It will collect all of these and finally zip the files up into a easy to transport zip file.
        If you need to collect more logs than just Application, System, and Operations Manager. Please change line 79 [String[]]$Logs.
    
    .PARAMETER Servers
        Add DNS Hostnames you would like to retrieve the Event Logs from like this: Agent1.contoso.com, Agent2.contoso.com
    
    .PARAMETER Logs
        Gather specific Event Logs from Remote or Local Machine.
    
    .PARAMETER CaseNumber
        Set the casenumber you would like to save with the filename in the output.
    
    .EXAMPLE
        PS C:\> .\Get-EventLogs.ps1 -Servers Agent1.contoso.com, Agent2.contoso.com -Logs Application, System
    
    .NOTES
        Additional information about the file.
        
        Last Modified: 1/14/2022
        
        .AUTHOR
            Blake Drumm (blakedrumm@microsoft.com)

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false,
			   Position = 1)]
	[String[]]$Servers,
	[Parameter(Mandatory = $false,
			   Position = 2)]
	[String[]]$Logs,
	[Parameter(Mandatory = $false,
			   Position = 3)]
	[string]$CaseNumber,
	[Parameter(Mandatory = $false,
			   Position = 4)]
	[string]$OutputPath
)
#>
# --------------------------------------------------------------------
# --------------------------------------------------------------------

if ($Servers)
{
	$DefinedServers = $Servers
}

# Replace Write-Host with Write-Console
Write-Console -Text "Gathering Event Logs" -ForegroundColor Cyan

function Get-EventLogs
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[String[]]$Servers,
		[Parameter(Mandatory = $false,
				   Position = 2)]
		[String[]]$Logs,
		[Parameter(Mandatory = $false,
				   Position = 3)]
		[string]$CaseNumber,
		[Parameter(Mandatory = $false,
				   Position = 4)]
		[string]$OutputPath
	)
	
	# Modify this if you need more logs
	if ($Logs -eq $null)
	{
		[String[]]$Logs = 'Application', 'Setup', 'System', 'Windows PowerShell', 'Microsoft-SMA/Operational', 'Microsoft-Automation/Operational', 'Microsoft-Windows-WindowsUpdateClient/Operational', 'Operations Manager', 'OMS Gateway Log'
	}
	
	if (-NOT $OutputPath)
	{
		$OutputPath = "$env:USERPROFILE\Desktop\Event Log Output"
	}
	
	if ($CaseNumber)
	{
		# Removes only a trailing backslash if it exists and then appends the case number
		if ($OutputPath.EndsWith('\'))
		{
			$OutputPath = $OutputPath.Substring(0, $OutputPath.Length - 1)
		}
		$OutputPath = "$OutputPath - $CaseNumber"
	}
	else
	{
	}
	
	IF (!(Test-Path $OutputPath))
	{
		Write-Console -MessageSegments @(
			@{ Text = "Creating folder: "; ForegroundColor = "DarkYellow" },
			@{ Text = "$OutputPath"; ForegroundColor = "DarkCyan" }
		)
		New-Item -Type 'Directory' -Path $OutputPath | Out-Null
	}
	else
	{
		Write-Console -Text "Folder already exists. Attempting to delete the path: $OutputPath" -ForegroundColor DarkYellow
		Remove-Item $OutputPath -Force -Recurse -Confirm:$false
		if (-NOT (Test-Path $OutputPath))
		{
			Write-Console -Text "Folder has been deleted successfully." -ForegroundColor Gray
			New-Item -Type 'Directory' -Path $OutputPath | Out-Null
		}
	}
	if ($servers)
	{
		$servers = $servers | Select-Object -Unique | Sort-Object
	}
	else
	{
		$servers = $env:COMPUTERNAME
	}
	foreach ($server in $servers)
	{
		Write-Console -Text "$server" -ForegroundColor Green
		foreach ($log in $logs)
		{
			if ($server -notmatch $env:COMPUTERNAME)
			{
				try
				{
					if ($log -like '*/*')
					{ $logname = $log.split('/')[0] }
					else { $logname = $log }
					Invoke-Command -ComputerName $server {
						# Corrected Time-Stamp function without trailing hyphen
						Function Time-Stamp
						{
							$TodaysDate = Get-Date
							return "$($TodaysDate.ToShortDateString()) $($TodaysDate.ToLongTimeString())"
						}
						trap
						{
							Write-Warning "$(Time-Stamp)$($error[0]) at line $($_.InvocationInfo.ScriptLineNumber)"
						}
						IF (!(Test-Path $using:OutputPath))
						{
							Write-Console -MessageSegments @(
								@{ Text = " Creating output folder on remote server: "; ForegroundColor = "DarkYellow" },
								@{ Text = "$using:OutputPath"; ForegroundColor = "DarkCyan" }
							)
							mkdir $using:OutputPath | Out-Null
						}
						$fileCheck = test-path "$using:OutputPath\$using:server`.$using:logname.evtx"
						if ($fileCheck)
						{
							Remove-Item "$using:OutputPath\$using:server`.$using:logname.evtx" -Force
						}
						Write-Console -MessageSegments @(
							@{ Text = "  Exporting log: " },
							@{ Text = $using:log; ForegroundColor = "Magenta" }
						)
						wevtutil epl $using:log "$using:OutputPath\$using:server.$using:logname.evtx"
						wevtutil al "$using:OutputPath\$using:server`.$using:logname.evtx"
					} -ErrorAction Stop
					$fileCheck2 = test-path "$OutputPath\$server" -ErrorAction Stop
					if (!($fileCheck2))
					{
						New-Item -ItemType directory -Path "$OutputPath" -Name "$server" -ErrorAction Stop | Out-Null
					}
					$UNCPath = ($OutputPath).Replace(":", "$")
					Move-Item "\\$server\$UNCPath\$server.$logname.evtx" "$OutputPath" -force -ErrorAction Stop
					#"Get-ChildItem \\$server\c$\Users\$env:USERNAME\Desktop\localemetadata\"
					Get-ChildItem "\\$server\$UNCPath\localemetadata\" -ErrorAction Stop |
					Where-Object { $_.name -like "*$server*" -and $_.name -like "*$logname*" } |
					Move-Item -Destination "$OutputPath\localemetadata\" -force -ErrorAction Stop
				}
				catch
				{
					Write-Warning "$(Time-Stamp)$($error[0]) at line $($_.InvocationInfo.ScriptLineNumber)"
					break
				}
				
			}
			else
			{
				try
				{
					if ($log -like '*/*')
					{ $logname = $log.split('/')[0] }
					else { $logname = $log }
					$fileCheck = test-path "$OutputPath\$server.$logname.evtx"
					if ($fileCheck -eq $true)
					{
						Remove-Item "$OutputPath\$server.$logname.evtx" -Force | Out-Null
					}
					Write-Console -MessageSegments @(
						@{ Text = "  Exporting log: " },
						@{ Text = $log; ForegroundColor = "Magenta" }
					)
					$PreviousErrorActionPreference = $ErrorActionPreference
					try
					{
						$ErrorActionPreference = 'Stop'
						# Redirect all output and errors to $null
						wevtutil epl $log "$OutputPath\$server.$logname.evtx" *> $null
						wevtutil al "$OutputPath\$server.$logname.evtx" *> $null
						
						Move-Item "$OutputPath\$server.$logname.evtx" "$OutputPath" -force -ErrorAction Stop
						Get-ChildItem "$OutputPath\localemetadata\" |
						Where-Object { $_.name -like "*$server*" -and $_.name -like "*$logname*" } |
						Move-Item -Destination "$OutputPath\localemetadata\" -force
					}
					catch
					{
						$logText = $log.ToString().Replace("/", ".")
						Write-Console -Text "  Unable to locate $logText event logs on $server."
						$_ | Out-FileWithErrorHandling -FilePath "$OutputPath`\Unable to locate $logText event logs on $server"
						continue
					}
					$ErrorActionPreference = $PreviousErrorActionPreference
				}
				catch
				{
					Write-Warning "$(Time-Stamp)$($error[0]) at line $($_.InvocationInfo.ScriptLineNumber)"
					break
				}
			}
		}
		Remove-Item "\\$server\$UNCPath" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
	}
	<#
	#Zip output
	Write-Host "$(Time-Stamp)Zipping up Output." -ForegroundColor DarkCyan
	[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
	[System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null
	$SourcePath = Resolve-Path "$OutputPath"
	
	$date = Get-Date -Format "MM.dd.yyyy-hh.mmtt"
	$Mod = "EventLogs" + "-" + $date
	[string]$destfilename = "$Mod`.zip"
	
	[string]$destfile = "$OutputPath\$destfilename"
	if (Test-Path $destfile)
	{
		#File exists from a previous run on the same day - delete it
		Write-Host "$(Time-Stamp)Found existing zip file: $destfile." -ForegroundColor DarkGreen
		Write-Host "$(Time-Stamp)Deleting existing file." -ForegroundColor Gray
		Remove-Item $destfile -Force
	}
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	$includebasedir = $false
	[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $destfile, $compressionLevel, $includebasedir) | Out-Null
	Write-Host "$(Time-Stamp)Saved zip file to: $destfile`." -ForegroundColor Cyan
	Remove-Item $OutputPath -Recurse
	#>
	#Write-Warning "Exiting script..."
	#Start-Process C:\Windows\explorer.exe -ArgumentList "/select, $OutputPath"
}
