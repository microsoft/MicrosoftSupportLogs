$WindowsUpdateFolder = "$outputFolder`Windows_Update\"
Create-Folder $WindowsUpdateFolder

if ($GetUpdateInfo)
{
	$UpdateInfoPath = "$outputFolder`Update_Info.txt"
	$UpdateInfo = $UpdateInfoPath
	
	# Write header to the update info file
	@"
============================================================================================================================================================================================
Data collected at UTC: $((Time-Stamp -UniversalTime)) / Local Time: $(Time-Stamp) / From Computer: $env:COMPUTERNAME
"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Width 4096
	
	# Recent Reboot Events
	# Create a query to get only the last 10 Event ID 1074 events from the System log
	$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
		"System", [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[(EventID=1074)]]"
	)
	
	# Create the reader to execute the query
	$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
	
	# Create a collection to store the recent events
	$events = @()
	
	# Loop through the events, but stop after collecting the last 10 events
	while (($event = $reader.ReadEvent()) -and ($events.Count -lt 10))
	{
		# Create a custom object with relevant data
		$events += [PSCustomObject]@{
			EventId	    = $event.Id
			TimeCreated = $event.TimeCreated
			Message	    = $event.FormatDescription()
		}
	}
	
	# Prepare the reboot data for output
	$rebootData = $events | Sort-Object TimeCreated -Descending
	
	# Define Operation and Result Codes
	$operation = @('Unk', 'Installation', 'Uninstallation', 'Other')
	$resultCode = @('Unk', 'In Progress', 'Succeeded', 'Succeeded With Errors', 'Failed', 'Aborted')
	
	Write-Console -MessageSegments @(
		@{ Text = "Collecting update information from ComObject Microsoft.Update"; ForegroundColor = "Cyan" }
	)
	
	# Update History	
	$updateSession = New-Object -ComObject Microsoft.Update.Session
	$updateSearcher = $updateSession.CreateUpdateSearcher()
	$historyCount = $updateSearcher.GetTotalHistoryCount()
	$filterOutString = "*defender antivirus*"
	
	$allUpdatesExceptDefender = $updateSearcher.QueryHistory(0, $historyCount) |
	Select-Object Date,
				  @{ N = 'Operation'; E = { $operation[$_.operation] } },
				  @{ N = 'Status'; E = { $resultCode[$_.resultcode] } },
				  Title, ClientApplicationID, ServerSelection, Type |
	Where-Object {
		![String]::IsNullOrWhiteSpace($_.title) -and
		($_.title -notlike $filterOutString -and $_.title -notlike "*- Printer -*")
	} |
	Sort-Object Date -Descending -Unique
	
	$last2DefenderUpdates = $updateSearcher.QueryHistory(0, $historyCount) |
	Select-Object Date,
				  @{ N = 'Operation'; E = { $operation[$_.operation] } },
				  @{ N = 'Status'; E = { $resultCode[$_.resultcode] } },
				  Title, ClientApplicationID, ServerSelection |
	Where-Object {
		![String]::IsNullOrWhiteSpace($_.title) -and
		$_.title -like $filterOutString
	} |
	Sort-Object Date -Descending -Unique |
	Select-Object -First 2 |
	Format-Table -AutoSize |
	Out-String -Width 300
	
	# Search Installed and Not Installed Updates
	$SearchResult = $updateSearcher.Search("Type='Software'")
	$installedAndNotInstalled = $SearchResult.Updates |
	Sort-Object LastDeploymentChangeTime, IsInstalled, Title -Descending |
	Format-Table @{ Label = 'ReleaseDate'; Expression = { ($_.LastDeploymentChangeTime).ToShortDateString() } },
				 Title,
				 @{ Label = 'InstallationStatus'; Expression = { if ($_.IsInstalled) { "Installed" }
			else { "Not Installed" } } },
				 @{
		Label = 'RebootStatus'; Expression = {
			if ($_.RebootRequired)
			{
				"Reboot required"
			}
			else
			{
				"No reboot required"
			}
		}
	},
				 AutoSelection,
				 AutoDownload,
				 IsPresent -AutoSize |
	Out-String -Width 300
	
	# Append data to the update info file
	# Software Updates
	@"
============================================================================================================================================================================================
Software Updates
"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	$installedAndNotInstalled | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	@"
To see additional detail filter the system event log with the following event id's: 1074, 26, 6006, 6009, 19, 20, 2004, 1022, 43, 109

"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	# Past 4 months of updates except Defender and Printer updates
	@"
============================================================================================================================================================================================
Past 4 months of updates with ClientApplicationID that initiated update, except Microsoft Defender updates and '- Printer -' updates
"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	$StartDate = (Get-Date).AddMonths(-4)
	$allUpdatesExceptDefender | Where-Object { $_.Date -gt $StartDate } |
	Format-Table -AutoSize | Out-String -Width 4096 | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	# Client Application ID Reference
	$ClientApplicationID = @'
NOTE: The Windows Update Service is used to install updates, however it is the ClientApplicationID that initiates the request to the Windows Update Service. 
      The following Table can be used to help establish the application that initiated the request to the Windows Update Service.

ClientApplicationID                             Process Initiating the Request to the Windows Update Service
===================                             =================================================================================
AutomaticUpdatesWuApp                           Windows Update Application - Component responsible for automatic update checks and installations in Windows Update service
Azure VM Guest Patching                         Azure VM Guest Patching feature initiating updates on Azure virtual machines.
CcmExec                                         Configuration Manager (SCCM) Client Agent Host service (Microsoft Endpoint Configuration Manager client), responsible for initiating software update scans and installation.
ITSecMgmt                                       Windows Security (Defender) - Initiates security updates and scans
MoUpdateOrchestrator                            Modern Update Orchestrator - Part of the Windows Update system that handles updates for Windows 10 and newer versions, including Windows Server 2016 and later.
OperationalInsights                             Azure Log Analytics Agent (formerly OMS) initiating updates via Update Management
SqlIaaSExtension.Service.exe                    Azure SQL Virtual Machine Extension - Manages SQL Server updates
SUS Client                                      Software Update Services Client - Refers to Windows Server Update Services (WSUS) client interactions
Update                                          Windows Update Agent - Local Windows Update process responsible for detecting, downloading, and installing updates.
UpdateAgentLCU                                  Used internally by Windows Update for installing Servicing Stack Updates (SSUs) and Cumulative Updates
UpdateManagementActionExec.exe                  Azure VM Guest Patching - Part of 'Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension' extension
UpdateManagement_Patch-MicrosoftOMSComputer     Azure Automation Update Management (v1) initiating Windows Update Service to install updates
UpdateOrchestrator                              Update Orchestrator Service (UsoSvc) - Core Windows service managing scanning, downloading, installing, and scheduling of Windows Updates
UsoClient                                       Update Session Orchestrator Client - Windows Update client utility
Windows Defender                                Updates initiated by Windows Defender Antivirus (now Microsoft Defender Antivirus) for malware definitions
WindowsOsUpdateExtension                        Azure Arc-enabled servers Update Management Extension initiating updates
wusa                                            Windows Update Standalone Installer - Used for manual installation of update packages (.msu files)

If you do not want Azure VMGuest Patching to randomly install updates after 10 PM local Regional time change the system to "Customer managed Schedules" in Update Manager

'@
	$ClientApplicationID | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	# Recent system Event ID 1074 records
	@"
============================================================================================================================================================================================
Recent system Event ID 1074 records:
"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	$rebootData | Format-Table -Wrap | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	# Two most recent Microsoft Defender updates
	@"
============================================================================================================================================================================================
Two most recent Microsoft Defender updates:
"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	$last2DefenderUpdates | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	
	#region Client Application ID's Available to System
	@"
============================================================================================================================================================================================
Available Client Application ID's:

"@ | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	# Create update session and searcher
	$updateSession = New-Object -ComObject Microsoft.Update.Session
	$updateSearcher = $updateSession.CreateUpdateSearcher()
	
	# Get total history count
	$historyCount = $updateSearcher.GetTotalHistoryCount()
	
	# Query the update history
	$updateHistory = $updateSearcher.QueryHistory(0, $historyCount)
	
	# Extract unique ClientApplicationIDs
	$clientAppIds = $updateHistory |
	Select-Object -ExpandProperty ClientApplicationID |
	Where-Object { $_ -and $_.Trim() -ne "" } |
	Sort-Object -Unique
	
	# Display the list
	$clientAppIds | ForEach-Object {
		"ClientApplicationID: $_ (Source process for update operations)"
	} | Out-FileWithErrorHandling -FilePath $UpdateInfo -Append -Width 4096
	#endregion Client Application ID's Available to System
	
	# Copy the update info file to the Windows Update folder
	Copy-File -Quiet -SourcePath $UpdateInfoPath -DestinationPath $WindowsUpdateFolder
	
	#region Windows Update Settings
	$WinUpdateSettings = "$WindowsUpdateFolder\Windows_Update_Settings.txt"
	
	$AutoUpdateNotificationLevels = @{
		0 = "Not configured";
		1 = "Disabled";
		2 = "Notify before download";
		3 = "Notify before installation";
		4 = "Scheduled installation"
	}
	$AutoUpdateDays = @{
		0 = "Every Day";
		1 = "Every Sunday";
		2 = "Every Monday";
		3 = "Every Tuesday";
		4 = "Every Wednesday";
		5 = "Every Thursday";
		6 = "Every Friday";
		7 = "Every Saturday"
	}
	
	$AUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
	
	$AUObj = [PSCustomObject]@{
		NotificationLevel	  = $AutoUpdateNotificationLevels[$AUSettings.NotificationLevel]
		UpdateDays		      = $AutoUpdateDays[$AUSettings.ScheduledInstallationDay]
		UpdateHour		      = $AUSettings.ScheduledInstallationTime
		'Recommended updates' = if ($AUSettings.IncludeRecommendedUpdates) { "Included" } else { "Excluded" }
	}
	
	# Output the settings to the file
	$AUSettings | Out-FileWithErrorHandling -FilePath $WinUpdateSettings -Append
	$AUObj | Format-Table * | Out-FileWithErrorHandling -FilePath $WinUpdateSettings -Append
	#endregion Windows Update Settings
	
	#region Windows Update Registry
	$RegoutputFile = "$outputFolder`REG-WindowsUpdate.txt"
	if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")
	{
		# Use Start-Process to run REG EXPORT and suppress output without redirection operators
		$regExportCommand = "EXPORT `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`" `"$RegoutputFile`" /y"
		Start-Process -FilePath "REG" -ArgumentList $regExportCommand -NoNewWindow -Wait -ErrorAction Stop | Out-Null
		
		@"

-------------------------------------------------------------------------

More information: https://learn.microsoft.com/windows/deployment/update/waas-wu-settings

---------------------------------

NoAutoUpdate (REG_DWORD):

0: Automatic Updates is enabled (default).

1: Automatic Updates is disabled. // This setting is applied when switching the system to 'Customer Managed Schedule,' but customers can modify it later, and their changes will be retained.

---------------------------------

AUOptions (REG_DWORD):

1: Keep my computer up to date is disabled in Automatic Updates.

2: Notify of download and installation.

3: Automatically download and notify of installation.

4: Automatically download and scheduled installation.

5: Allow local admin to select the configuration mode. This option isn't available for Windows 10 or later versions.

7: Notify for install and notify for restart. (Windows Server 2016 and later only)

---------------------------------

ScheduledInstallEveryWeek (REG_DWORD):

0: Do not enforce a once-per-week scheduled installation.
1: Enforce automatic installations once a week on the specified day and time.
(Requires ScheduledInstallDay and ScheduledInstallTime to be set.)

---------------------------------

ScheduledInstallDay (REG_DWORD):

0: Every day.

1 through 7: The days of the week from Sunday (1) to Saturday (7).

---------------------------------

ScheduledInstallTime (REG_DWORD):

n, where n equals the time of day in a 24-hour format (0-23).

---------------------------------

UseWUServer (REG_DWORD)

Set this value to 1 to configure Automatic Updates to use a server that is running Software Update Services instead of Windows Update.

---------------------------------

RescheduleWaitTime (REG_DWORD)

m, where m equals the time period to wait between the time Automatic Updates starts and the time that it begins installations where the scheduled times have passed. The time is set in minutes from 1 to 60, representing 1 minute to 60 minutes)

---------------------------------

NoAutoRebootWithLoggedOnUsers (REG_DWORD):

0 (false) or 1 (true). If set to 1, Automatic Updates doesn't automatically restart a computer while users are logged on.
"@ | Out-FileWithErrorHandling -Force -Append -FilePath $RegoutputFile
    }
    else
    {
        "'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' Not present" | Set-Content -Path $RegoutputFile
    }
    Copy-Item -Path $RegoutputFile -Destination $WindowsUpdateFolder | Out-Null
	#endregion Windows Update Registry
	
	#region Copy CBS Logs
	Copy-File -SourcePath "C:\windows\logs\cbs\*.log" -DestinationPath "$WindowsUpdateFolder\CBS"
	#endregion Copy CBS Logs
	
	#region Copy DISM Logs
	Copy-File -SourcePath "C:\windows\logs\DISM\*.log" -DestinationPath "$WindowsUpdateFolder\DISM" -MostRecentFileCount 10
	#endregion Copy DISM Logs
}
