#region Copy OS Miscellaneous Logs
$miscFolder = "$outputFolder`OS-Miscellaneous\"
Create-Folder $miscFolder
$ENVfileoutput = "$miscFolder`Environmental-Variables.txt"
"$script:CRLF=========================================================================$script:CRLF`== All available environmental variables$script:CRLF`----------------------------------------------------------" | Out-FileWithErrorHandling -FilePath $ENVfileoutput
Get-ChildItem env: | Format-Table -AutoSize | Out-FileWithErrorHandling -FilePath $ENVfileoutput -Append
"$script:CRLF=========================================================================$script:CRLF`== List paths in the PSModulePath environmental variable$script:CRLF`----------------------------------------------------------" | Out-FileWithErrorHandling -FilePath $ENVfileoutput -Append
($env:PSModulePath).Split(";") | ForEach-Object { $_.Trim() } | ForEach-Object {
	if ($_.LastIndexOfAny("\") -ne ($_.Length - 1)) { $_ + "\" }
	else { $_ }
} | Out-FileWithErrorHandling -FilePath $ENVfileoutput -Append
"$script:CRLF=========================================================================$script:CRLF`== List paths in the Path environmental variable$script:CRLF`----------------------------------------------------------" | Out-FileWithErrorHandling -FilePath $ENVfileoutput -Append
($env:Path).Split(";") | ForEach-Object { $_.Trim() } | ForEach-Object {
	if ($_.LastIndexOfAny("\") -ne ($_.Length - 1)) { $_ + "\" }
	else { $_ }
} | Out-FileWithErrorHandling -FilePath $ENVfileoutput -Append
#endregion Copy OS Miscellaneous Logs

#region Services Details
Write-Console -MessageSegments @(
	@{ Text = "Gathering Services details"; ForegroundColor = "Cyan" }
)
$servicestxt = "$miscFolder`services.txt"
Try
{
	"================================================================================================================$script:CRLF`== Summary of a few services at UTC time: $(Time-Stamp -UniversalTime)$script:CRLF`----------------------------------------------------------" | Out-FileWithErrorHandling -FilePath $servicestxt
	Get-Service healthservic*, HybridWorker*, ExtensionServi*, GCArcServi*, himd*, *gateway | Sort-Object DisplayName | Format-Table -AutoSize | Out-FileWithErrorHandling -FilePath $servicestxt -Append
	$serviceDetails = Get-CimInstance Win32_Service
	# Get the total number of services
	$serviceCount = $serviceDetails.Count
	"================================================================================================================$script:CRLF`== All service details ($serviceCount services)$script:CRLF`----------------------------------------------------------" | Out-FileWithErrorHandling -FilePath $servicestxt -Append
	
	$i = 0 # Initialize an index counter
	
	$serviceDetails | ForEach-Object {
		# Get process start time if service is running
		$startTime = if ($_.State -eq 'Running' -and $_.ProcessId)
		{
			try
			{
				(Get-Process -Id $_.ProcessId -ErrorAction Stop).StartTime
			}
			catch
			{
				"Unable to determine"
			}
		}
		else
		{
			"Not Running"
		}
		
		# Get the last start/stop events from event log
		$lastEvents = Get-WinEvent -FilterHashtable @{
			LogName	     = 'System'
			ID		     = @(7036, 7040)
			ProviderName = 'Service Control Manager'
		} -MaxEvents 1 -ErrorAction SilentlyContinue |
		Where-Object { $_.Message -like "*$($_.Name)*" }
		
		$lastEventTime = if ($lastEvents)
		{
			$lastEvents[0].TimeCreated
		}
		else
		{
			"No recent events found"
		}
		
		# Get dependent services
		$dependentServices = (Get-Service $_.Name -ErrorAction SilentlyContinue).DependentServices
		$dependencies = (Get-Service $_.Name -ErrorAction SilentlyContinue).ServicesDependedOn
		
		# Select the desired properties for each service
		$_ | Select-Object Name, DisplayName, State, ExitCode,
						   @{ Name = 'Log on as'; Expression = { $_.StartName } },
						   @{ Name = 'Current Start Time'; Expression = { $startTime } },
						   @{ Name = 'Last Event Time'; Expression = { $lastEventTime } },
						   @{ Name = 'Dependencies'; Expression = { if ($dependencies) { $dependencies.Name -join ', ' }
				else { 'None' } } },
						   @{ Name = 'Dependent Services'; Expression = { if ($dependentServices) { $dependentServices.Name -join ', ' }
				else { 'None' } } },
						   PathName,
						   ServiceType,
						   StartMode,
						   @{ Name = 'Description'; Expression = { $_.Description } },
						   @{ Name = 'DelayedAutoStart'; Expression = { $_.DelayedAutoStart } },
						   @{ Name = 'ErrorControl'; Expression = { $_.ErrorControl } }
		
		# Increment the index counter
		$i++
		
		# Output separator unless it's the last item
		if ($i -lt $serviceCount)
		{
			'----------------------------------------'
			''
		}
	} | Out-FileWithErrorHandling -FilePath $servicestxt -Append
}
Catch { Write-Verbose $_ }
#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 50

# Windows Time Information
Try
{
	Write-Console -MessageSegments @(
		@{ Text = "Gathering Windows Time details"; ForegroundColor = "Cyan" }
	)
	"How accurate is the UTC time: " + (Time-Stamp -UniversalTime) | Out-FileWithErrorHandling -FilePath "$outputFolder`WindowsTime.txt"
	"If the time is off by several minutes it can cause authentication issues$script:CRLF=========================================================================$script:CRLF" | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	$ntpServer = 'time.windows.com'
	$windowsTime = w32tm /stripchart /computer:$ntpServer /samples:4
	$windowsTime | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	$windowsTime = $windowsTime | Out-String -Width 2048
	if ($windowsTime -notmatch "error: 0x800705B4")
	{
		@"
                             ^
                              \
                                The 0: value is the number of seconds different from real time.
"@ | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	}
	elseif ($windowsTime -match "No such host is known. (0x80072AF9)")
	{
		@"
                     ^
                      \ 
                        Unable to resolve the hostname: $ntpServer
"@ | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	}
	else
	{
		@"
          ^
           \ 
             An error indicates we were unable to check the computer time against the NTP server, not that it is wrong. (0x800705B4: ERROR_TIMEOUT)
"@ | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	}
	"$script:CRLF=========================================================================$script:CRLF" | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
	$w32tmConfig = w32tm /query /configuration
	$w32tmConfig | Out-FileWithErrorHandling "$outputFolder`WindowsTime.txt" -Append
}
Catch { }
#endregion Services Details

#region RSA Machine Keys Permissions
Write-Console -MessageSegments @(
	@{ Text = "Gathering RSA Machine Keys permissions"; ForegroundColor = "Cyan" }
)
$RSAOutputFile = "$miscFolder`RSA-MachineKeys_Permissions.txt"
"Local Time: " + (Time-Stamp) + "    Universal Time: " + (Time-Stamp -UniversalTime) + $script:CRLF | Out-FileWithErrorHandling -FilePath $RSAOutputFile
"Use this file if you get an error similar to:  Could not create SSL/TLS secure channel " | Out-FileWithErrorHandling -FilePath $RSAOutputFile -Append
"to confirm $path and the subfiles have the correct permissions $script:CRLF " | Out-FileWithErrorHandling -FilePath $RSAOutputFile -Append
$path = (Get-Item -Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys").FullName

#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 46

"Folder: $($path)"  | Out-FileWithErrorHandling -FilePath $RSAOutputFile -Append
(Get-Acl -Path $path).Access  | Out-FileWithErrorHandling -FilePath $RSAOutputFile -Append
$Subfolders = Get-ChildItem -Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
foreach ($sub in $Subfolders)
{
	$acl = (Get-Acl -Path $sub.FullName).Access
	if ($acl.IdentityReference[0] -eq "NT AUTHORITY\SYSTEM")
	{
		"File: $($sub.Name) User: $($acl.IdentityReference[0]) Perms: $($acl.FileSystemRights[0])"  | Out-FileWithErrorHandling -FilePath $RSAOutputFile -Append
	}
}
#endregion RSA Machine Keys Permissions

#region Group Policy Result (gpresult)
Write-Console -MessageSegments @(
	@{ Text = "Gathering Group Policy Result (gpresult)"; ForegroundColor = "Cyan" }
)
try
{
	$GPresultPath = "$miscFolder`Group-Policy\"
	Create-Folder -path $GPresultPath
	$GPresultTxt = "$GPresultPath$($env:COMPUTERNAME)-GPResult-Z.txt"
	$GPresultHtml = "$GPresultPath$($env:COMPUTERNAME)-GPResult.html"
	
	Write-Console -MessageSegments @(
		@{ Text = "gpresult /Z" }
	)
	# Run GPResult with /Z (Text Output)
	Start-Process -FilePath "GPResult.exe" `
				  -WorkingDirectory "C:\Windows\System32" `
				  -ArgumentList "/Z" `
				  -ErrorAction Stop `
				  -Wait `
				  -NoNewWindow `
				  -RedirectStandardOutput $GPresultTxt
	
	Write-Console -MessageSegments @(
		@{ Text = "gpresult /H `"$GPresultHtml`"" }
	)
	# Run GPResult with /H (HTML Output)
	Start-Process -FilePath "GPResult.exe" `
				  -WorkingDirectory "C:\Windows\System32" `
				  -ArgumentList @("/H", "`"$GPresultHtml`"") `
				  -ErrorAction Stop `
				  -Wait `
				  -Verb RunAs
}
catch
{
	Write-Console "Failure occurred while gathering group policy: $_" -ForegroundColor Yellow
}
#endregion Group Policy Result (gpresult)

#region Misc.txt
$Misc = "$miscFolder`Misc.txt"

# Try to retrieve the Win32_OperatingSystem information
try
{
	$win32OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
	
	# Check if $win32OS.LastBootUpTime exists and calculate uptime
	if ($win32OS.LastBootUpTime)
	{
		$lastBootLocalTime = $win32OS.LastBootUpTime.ToLocalTime()
		$uptime = New-TimeSpan -Start $lastBootLocalTime
		$uptimeString = @()
		
		# Using single-line pluralization for each component
		if ($uptime.Days -gt 0)
		{
			$uptimeString += "$($uptime.Days) day$(if ($uptime.Days -ne 1) { 's' }
				else { '' })"
		}
		if ($uptime.Hours -gt 0)
		{
			$uptimeString += "$($uptime.Hours) hour$(if ($uptime.Hours -ne 1) { 's' }
				else { '' })"
		}
		if ($uptime.Minutes -gt 0)
		{
			$uptimeString += "$($uptime.Minutes) minute$(if ($uptime.Minutes -ne 1) { 's' }
				else { '' })"
		}
		if ($uptime.Seconds -gt 0)
		{
			$uptimeString += "$($uptime.Seconds) second$(if ($uptime.Seconds -ne 1) { 's' }
				else { '' })"
		}
		
		# Join the parts with commas and 'and' before the last item
		if ($uptimeString.Count -gt 1)
		{
			$uptimeFormatted = ($uptimeString[0 .. ($uptimeString.Count - 2)] -join ', ') + " and " + $uptimeString[-1]
		}
		else
		{
			$uptimeFormatted = $uptimeString[0]
		}
		
		# Extract components for LastBootUpTime formatting
		$month = $lastBootLocalTime.Month
		$day = $lastBootLocalTime.Day
		$year = $lastBootLocalTime.Year
		$hour = $lastBootLocalTime.Hour % 12
		if ($hour -eq 0) { $hour = 12 }
		$minute = $lastBootLocalTime.Minute.ToString().PadLeft(2, '0')
		$second = $lastBootLocalTime.Second.ToString().PadLeft(2, '0')
		$amPm = if ($lastBootLocalTime.Hour -ge 12) { "PM" }
		else { "AM" }
		$timeZoneAbbreviation = [System.TimeZoneInfo]::Local.StandardName
		
		# Format the last boot-up time with the time zone
		$lastBootWithTimeZone = "$month/$day/$year $hour`:$minute`:$second $amPm ($timeZoneAbbreviation)"
		
		# Write the formatted uptime and local boot time to the log file
		$SystemUptime = "$uptimeFormatted (Last boot up time: $lastBootWithTimeZone)"
	}
	else
	{
		$SystemUptime = "Unable to retrieve LastBootUpTime"
	}
	
	$win32OS_MemoryUtilized = "$([math]::Round(($win32OS.TotalVisibleMemorySize / 1KB / 1KB) - ($win32OS.FreePhysicalMemory / 1KB / 1KB), 2)) out of $([math]::Round($win32OS.TotalVisibleMemorySize / 1KB / 1KB, 2)) GB"
}
catch
{
	# Log an error if Win32_OperatingSystem retrieval fails
	$errorObject = [PSCustomObject]@{
		"Computer Name" = $([System.Net.Dns]::GetHostByName(($env:computerName)).HostName)
		"OS Version"    = "Unable to retrieve OS information"
		"Memory Utilized (GB)" = "Unknown"
		"System Uptime" = "Unknown"
		"Local Time"    = $(Time-Stamp -IncludeTimeZone)
		"Universal Time" = $(Time-Stamp -UniversalTime -IncludeTimeZone)
		"Script Version" = $version
	} | Format-List | Out-String -Width 2048
	
	# Output in list format to log file
	"===============================================$script:CRLF$errorObject$script:CRLF===============================================" |
	Out-FileWithErrorHandling -Force -FilePath $Misc
}

#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 9

# Construct a PSCustomObject with system information
if ($win32OS)
{
	$infoObject = ([PSCustomObject]@{
			"Computer Name" = $([System.Net.Dns]::GetHostByName(($env:computerName)).HostName)
			"OS Version"    = "$($win32OS.Caption) [$($win32OS.OSArchitecture)] ($($win32OS.Version))"
			"Memory Utilized (GB)" = "$win32OS_MemoryUtilized"
			"System Uptime" = $SystemUptime
			"Local Time"    = $(Time-Stamp -IncludeTimeZone)
			"Universal Time" = $(Time-Stamp -UniversalTime -IncludeTimeZone)
			"Script Version" = $version
		} | Format-List | Out-String -Width 2048).Trim()
	
	# Output in list format to log file
	"===============================================$script:CRLF`== General Information$script:CRLF-----------------------------------$script:CRLF$infoObject" |
	Out-FileWithErrorHandling -Force -FilePath $Misc
	
	# Append PowerShell version information
	# Determine the maximum property name length for alignment
	$maxNameLength = ($PSVersionTable.Keys | Measure-Object -Property Length -Maximum).Maximum
	
	# Iterate through each property in $PSVersionTable
	$PSVersionTableFormatted = foreach ($property in $PSVersionTable.GetEnumerator())
	{
		# Calculate padding based on max name length to align the output
		$namePadded = $property.Name.PadRight($maxNameLength)
		
		# Check if the property value is an array or collection
		if ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -notmatch 'String')
		{
			# Join array items with commas and display beside the colon
			"$namePadded : $([string]::Join(', ', $property.Value))"
		}
		else
		{
			# Display single values directly
			"$namePadded : $($property.Value)"
		}
	}
	
	"$script:CRLF===============================================$script:CRLF`== `$PSVersionTable$script:CRLF`-----------------------------------$script:CRLF$($PSVersionTableFormatted | Out-String -Width 2048)" |
	Out-FileWithErrorHandling -Append -FilePath $Misc
}

#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 10

#region Get PowerShell versions installed
# Define registry paths to check for Windows PowerShell versions
$psPaths = @(
	"HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine",
	"HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine"
)

# Initialize an array to store detected PowerShell versions as objects
$installedVersions = @()

# Loop through each path to check for Windows PowerShell versions
foreach ($path in $psPaths)
{
	if (Test-Path $path)
	{
		try
		{
			# Retrieve the PowerShellVersion property if it exists
			$version = (Get-ItemProperty -Path $path -ErrorAction Stop).PowerShellVersion
			if ($version)
			{
				# Add a custom object for Windows PowerShell version
				$installedVersions += [PSCustomObject]@{
					VersionType = "Windows PowerShell"
					Version	    = $version
				}
			}
		}
		catch
		{
			Write-Host "Error retrieving PowerShell version from $path" -ForegroundColor Yellow
		}
	}
}

# Check for PowerShell Core versions (PowerShell 6 and above)
$pwshCorePath = "HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions"
if (Test-Path $pwshCorePath)
{
	# Loop through each subkey under InstalledVersions for specific PowerShell Core versions
	foreach ($subkey in Get-ChildItem -Path $pwshCorePath)
	{
		try
		{
			$version = (Get-ItemProperty -Path $subkey.PSPath -ErrorAction Stop).SemanticVersion
			if ($version)
			{
				# Add a custom object for PowerShell Core version
				$installedVersions += [PSCustomObject]@{
					VersionType = "PowerShell Core"
					Version	    = $version
				}
			}
		}
		catch
		{
			Write-Host "Error retrieving PowerShell Core version from $($subkey.PSPath)" -ForegroundColor Yellow
		}
	}
}

# Display the custom objects for all detected PowerShell versions
"$script:CRLF===============================================$script:CRLF`== PowerShell versions detected$script:CRLF`-----------------------------------$script:CRLF$(($installedVersions | Sort-Object Version | Out-String).Trim())" | Out-FileWithErrorHandling -Append -FilePath $Misc
#endregion Get PowerShell versions installed

# Execute Various Cmdlets Safely
Try-Cmdlet Get-Process "$miscFolder`Get-Process.txt"

#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 11

#region PowerShell Modules
$ModuleListFile = "$miscFolder`PSModuleList.txt"
$ModuleListFileDetailed = "$miscFolder`PSModuleList-Detailed.txt"
Write-Console -MessageSegments @(
	@{ Text = "Checking PowerShell Modules"; ForegroundColor = "Cyan" }
)

#region Detailed PowerShell Modules Data
# Get all loaded modules and process them
"============================================================================$script:CRLF`== Detailed List of PowerShell modules loaded in memory, when the script ran" | Out-FileWithErrorHandling -Force -FilePath $ModuleListFileDetailed
$modules = Get-Module

#Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 12

$detailedModules = $modules | ForEach-Object {
	# Join the exported commands into a single string separated by commas
	$exportedCommands = $_.ExportedCommands.Values -join "$script:CRLF"
	
	# Create a custom object with the module details
	[PSCustomObject]@{
		ModuleType		     = $_.ModuleType
		Version			     = $_.Version
		Name				 = $_.Name
		Author			     = $_.Author
		Copyright		     = $_.Copyright
		Path				 = $_.Path
		Guid				 = $_.Guid
		CompatiblePSEditions = (($_.CompatiblePSEditions | Out-String) -join ", ").Trim()
		ExportedCommands	 = $exportedCommands
	}
}

# Output the formatted result with separators
$detailedModules | ForEach-Object {
	# Display a separator
	Write-Output "$script:CRLF`----------------------------------------$script:CRLF"
	
	# Format and display the module information
	$_ | Format-List
} | Out-FileWithErrorHandling -Append -FilePath $ModuleListFileDetailed
#endregion Detailed PowerShell Modules Data

#region Non-detailed PowerShell Modules Data
"===================================================================$script:CRLF`== List of PowerShell modules loaded in memory, when the script ran" | Out-FileWithErrorHandling -Force -FilePath $ModuleListFile
$modules | Out-FileWithErrorHandling -Force -Append -FilePath $ModuleListFile
"" | Out-FileWithErrorHandling -FilePath $ModuleListFile
"===============================$script:CRLF`== List of available modules" | Out-FileWithErrorHandling -FilePath $ModuleListFile
$PSModules = Get-Module -ListAvailable
$PSModules | Format-Table Name, Version, CompatiblePSEditions, DotNetFrameworkVersion | Out-FileWithErrorHandling -FilePath $ModuleListFile
#endregion PowerShell Modules Data
#endregion PowerShell Modules
#endregion Misc.txt

#region Gather Installed Programs
# Add additional property InstallDateObj that will hold the parsed DateTime object
try
{
	Write-Console "Gathering installed software" -ForegroundColor Cyan
	$Installed_Software = @()
	# Get 64bit installed software
	$Installed_Software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '64bit' } }
	$Installed_Software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj, @{ Name = 'Architecture'; Expression = { '32bit' } }
	
	$TheDate = (([datetime]::Now))
	     	<# Try to parse dates.
			$Installed_Software.ForEach({
					
					# add more formats if you need
					[string[]]$formats = @("yyyyMMdd", "MM/dd/yyyy")
					
					$installDate = $_.InstallDate
					$installedDateObj = $null;
					$formats.ForEach({
							[DateTime]$dt = New-Object DateTime; if ([datetime]::TryParseExact($installDate, $_, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt))
							{
								$installedDateObj = $dt
							} 
						});
					$_.InstallDateObj = $installedDateObj
				})
			#>
	$Installed_recently = @()
	$Installed_recently = $Installed_Software | Where-Object { ($null -ne $_.DisplayName) } # -or ($(try{($TheDate - $_.InstallDateObj).Days -le $Days}catch{$Test = $true}))) }
	$installedSoftwareResults = @()
	if ($Installed_recently.Count -gt 0)
	{
		foreach ($software in $Installed_recently)
		{
			$installedSoftwareResults += [pscustomobject]@{
				'Installed Software' = $software.DisplayName;
				#'Software Version'   = [version]$software.DisplayVersion;
				'Software Version'   = $software.DisplayVersion;
				'Publisher'		     = $software.Publisher;
				'Install Date'	     = $(try { $installedDate = [Datetime]::ParseExact($software.InstallDate, 'yyyyMMdd', $null) | Get-Date -UFormat "%m/%d/%Y"; Write-Verbose "Determined Install Date for $($software.DisplayName) to be: $installedDate"; $installedDate }
					catch { Write-Verbose "Unable to determine Install Date for $($software.DisplayName)" })
				Architecture		 = $software.Architecture;
			}
		}
	}
	else
	{
		$installedSoftwareResults += [pscustomobject]@{
			'Installed Software' = 'Nothing found.';
			'Software Version'   = $null;
			'Publisher'		     = $null;
			'Install Date'	     = $null;
			Architecture		 = $null;
		}
	}
	$installedSoftwareOutputDirectory = "$miscFolder`Installed-Software.txt"
	($installedSoftwareResults | Sort-Object -Property @{ Expression = 'Installed Software'; Descending = $false }, @{ Expression = 'Publisher'; Descending = $false }, @{ Expression = 'Software Version'; Descending = $true } | Format-Table * -AutoSize) | Out-FileWithErrorHandling -FilePath $installedSoftwareOutputDirectory -Force -Width 4096
}
catch
{
	Write-Console "Unable to gather installed software: $_" -ForegroundColor Red
}
#endregion Gather Installed Programs