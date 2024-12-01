try
{
	# Folder to save the Azure Arc Data
	$arcFolder = "$outputFolder`Azure_Arc"

	# Retrieve the service instance for 'himds'
	$service = Get-CimInstance -Verbose:$script:VerbosePreference -ClassName Win32_Service -Filter "Name='himds'" -ErrorAction Stop
	
	# Extract the PathName property
	$pathName = $service.PathName
	
	# Usage
	$azcmagentPath = $("$($pathName | split-path -ErrorAction Stop)\azcmagent.exe" -replace "`"", "")
}
catch
{
	$azcmagentPath = $null
	Write-Console -Text "Unable to locate the Azure Arc Agent on the machine." -ForegroundColor Gray
}

if ($azcmagentPath)
{
	$azcmagent = try { (Resolve-Path -Verbose:$script:VerbosePreference -ErrorAction Stop "$($azcmagentPath | Split-Path)\azcmagent.exe").Path } catch { Write-Console -Text "Unable to resolve Azure Arc Agent path" -ForegroundColor Gray }
	
	if (Test-Path $azcmagent)
	{
		Write-Console -Text "Found the Azure Arc executable" -ForegroundColor Green
		$AzcmagentCheckFile = "$arcFolder\Azcmagent_check.txt"
		
		Create-Folder $arcFolder
		& $azcmagent show | Out-FileWithErrorHandling -Width 2048 -Encoding utf8 -Force -FilePath "$arcFolder\Azcmagent_show.txt"
		
		$his_ip = ([System.Net.Dns]::GetHostAddresses("gbl.his.arc.azure.com"))[0].IPAddressToString
		
		# Check if IP starts with 10 or 172 and run 'azcmagent check' accordingly with or without '--enable-pls-check' flag
		if ($his_ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)')
		{
			if ($script:VerbosePreference -match "Continue|Stop")
			{
				& $azcmagent check --enable-pls-check --verbose | Out-FileWithErrorHandling -Width 2048 -Encoding utf8 -Force -FilePath $AzcmagentCheckFile
			}
			else
			{
				& $azcmagent check --enable-pls-check | Out-FileWithErrorHandling -Width 2048 -Encoding utf8 -Force -FilePath $AzcmagentCheckFile
			}
			
		}
		else
		{
			if ($script:VerbosePreference -match "Continue|Stop")
			{
				& $azcmagent check --verbose | Out-FileWithErrorHandling -Width 2048 -Encoding utf8 -Force -FilePath $AzcmagentCheckFile
			}
			else
			{
				& $azcmagent check | Out-FileWithErrorHandling -Width 2048 -Encoding utf8 -Force -FilePath $AzcmagentCheckFile
			}
			
		}
		
		
		
		Write-Console -MessageSegments @(
			@{ Text = "Gathering: "; ForegroundColor = "Cyan" },
			@{ Text = "azcmagent logs"; ForegroundColor = "DarkYellow" }
		)
		$azcmagentlogs = "$arcFolder\azcmagent-logs-$(Get-Date -Format yyMMddTHHmm)-$env:computername.zip"
		if (Test-Path "$arcFolder\azcmagent-logs*.zip" -Verbose:$script:VerbosePreference)
		{
			Remove-Item "$arcFolder\azcmagent-logs*.zip" -Verbose:$script:VerbosePreference
		}
		if ($script:VerbosePreference -match "Continue|Stop")
		{
			$azcmagentOutput = azcmagent logs -o $azcmagentlogs --verbose
		}
		else
		{
			$azcmagentOutput = azcmagent logs -o $azcmagentlogs
		}
		$azcmagentOutput
		$azcmagentOutput | Out-String | Out-FileWithErrorHandling "$outputFolder\script-log.log" -Append -Width 2048 -Encoding utf8
		
		Write-Console "Gathering Azure Arc installation log" -ForegroundColor Cyan
		Copy-File -Path "$env:Temp\installationlog.txt" -Destination $arcFolder
		Copy-File -Path "C:\ProgramData\AzureConnectedMachineAgent\" -Destination "$arcFolder"
	}
	else
	{
		Write-Console -Text "Unable to locate the Azure Arc executable" -ForegroundColor Yellow
		Create-Folder $arcFolder
		Copy-File "C:\WindowsAzure\Logs\WaAppAgent.log" "$arcFolder\VMLogs"
		Copy-File "C:\WindowsAzure\Logs\TransparentInstaller.log" "$arcFolder\VMLogs"
	}
	
	#region Get Azure Arc Config and Logs
	$arcConfigDirectory = Get-ItemPropertyValue -Verbose:$script:VerbosePreference -Path Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\71B380C23BD7D5D4DAA7D785868248FE -Name * -ErrorAction SilentlyContinue
	$arcLogDirectory = Get-ItemPropertyValue -Verbose:$script:VerbosePreference -Path Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0893E821F00CB004F88702441F7C44E7 -Name * -ErrorAction SilentlyContinue
	
	if ($arcConfigDirectory)
	{
		<#
		Create-Folder $arcFolder
		
		Write-Console -MessageSegments @(
			@{ Text = "Copying: "; ForegroundColor = "Green" },
			@{ Text = "$arcConfigDirectory"; ForegroundColor = 'DarkCyan' }
		)
		Copy-Item -Path $arcConfigDirectory -Destination $arcFolder -Recurse | Out-Null
		#>
		Copy-File -Path $arcConfigDirectory -Destination $arcFolder
	}
	
	if ($arcLogDirectory)
	{
		<#
		Create-Folder $arcFolder
		Write-Console -MessageSegments @(
			@{ Text = "Copying: "; ForegroundColor = "Green" },
			@{ Text = "$arcLogDirectory"; ForegroundColor = 'DarkCyan' }
		)
		Copy-Item -Path $arcLogDirectory -Destination $arcFolder -Recurse | Out-Null
		#>
		Copy-File -Path $arcLogDirectory -Destination $arcFolder
	}
	
	#endregion Get Azure Arc Logs and config
	
	#region Azure Arc Hotpatching	
	try
	{
		# Call the function for both registry paths
		Get-RegistryData -RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure Connected Machine Agent" `
						 -OutputFile "$arcFolder\REG-AzureConnectedMachineAgent.txt" `
						 -ErrorAction Stop
		
		Get-RegistryData -RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Hotpatch" `
						 -OutputFile "$arcFolder\REG-WindowsHotpatch.txt" `
		                 -ErrorAction Stop
	}
	catch
	{
		Write-Console -Text "Unable to gather Azure Arc Hotpatching information: $_" -ForegroundColor Gray
	}
	
	#endregion Azure Arc Hotpatching
}
	