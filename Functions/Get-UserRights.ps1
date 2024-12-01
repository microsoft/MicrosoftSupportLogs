<#
    .SYNOPSIS
        Retrieves local user account rights from the local or remote machine's security policy.

    .DESCRIPTION
        This script gathers the local security policy user rights assignments from the local machine or specified remote machines. It allows you to output the results to the console, a file (CSV or Text), or pass the results through the pipeline for further processing.

    .PARAMETER ComputerName
        Specifies a comma-separated list of servers to run this script against. To run locally, omit this parameter. This parameter accepts values from the pipeline.

    .PARAMETER UserName
        Specifies the usernames to filter the results. Use this parameter to retrieve user rights assignments for specific users. Provide the username in the format: domain\Username. If omitted, all user rights assignments will be retrieved.

    .PARAMETER FileOutputPath
        Specifies the location where the output file will be stored. Use this parameter in combination with -FileOutputType to define the output format.

    .PARAMETER FileOutputType
        Specifies the type of file to output. Valid options are 'CSV' or 'Text'. This parameter should be used with -FileOutputPath.

    .PARAMETER PassThru
        Indicates that the script should output the results as objects to the pipeline, allowing for further manipulation or filtering.

    .EXAMPLE
        Get local user account rights and output to the console:

            PS C:\> .\Get-UserRights.ps1

    .EXAMPLE
        Get user account rights from a remote server:

            PS C:\> .\Get-UserRights.ps1 -ComputerName SQL.contoso.com

    .EXAMPLE
        Get user account rights from the local machine and multiple remote servers:

            PS C:\> .\Get-UserRights.ps1 -ComputerName $env:COMPUTERNAME, SQL.contoso.com

    .EXAMPLE
        Get user account rights for specific users on a remote server:

            PS C:\> .\Get-UserRights.ps1 -ComputerName SQL.contoso.com -UserName CONTOSO\User1, CONTOSO\User2

    .EXAMPLE
        Output results to a CSV file in 'C:\Temp':

            PS C:\> .\Get-UserRights.ps1 -FileOutputPath C:\Temp -FileOutputType CSV

    .EXAMPLE
        Output results to a text file in 'C:\Temp':

            PS C:\> .\Get-UserRights.ps1 -FileOutputPath C:\Temp -FileOutputType Text

    .EXAMPLE
        Pass through objects and filter for a specific Privilege name:

            PS C:\> .\Get-UserRights.ps1 -ComputerName SQL.contoso.com -PassThru | Where-Object { $_.PrivilegeName -eq "Deny log on locally" }

    .NOTES
        Author: Blake Drumm (blakedrumm@microsoft.com)
        First Created on: June 10th, 2021
        Last Modified on: October 7th, 2024

        GitHub Repository:
        https://github.com/blakedrumm/SCOM-Scripts-and-SQL

        Exact Location:
        https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Get-UserRights.ps1
		
		------------------------------------------------------------------------------
		
		MIT License
		Copyright (c) Microsoft
		
		Permission is hereby granted, free of charge, to any person obtaining a copy
		of this software and associated documentation files (the "Software"), to deal
		in the Software without restriction, including without limitation the rights
		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
		copies of the Software, and to permit persons to whom the Software is
		furnished to do so, subject to the following conditions:
		
		The above copyright notice and this permission notice shall be included in all
		copies or substantial portions of the Software.
		
		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
		SOFTWARE.
		
	.LINK
	    https://blakedrumm.com/blog/set-and-check-user-rights-assignment/
#>
function Get-UserRights
{
	function Get-SecurityPolicy
	{
		param
		(
			$UserName
		)
		#requires -version 2
		# Fail script if we can't find SecEdit.exe
		$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
		if (-not (Test-Path $SecEdit))
		{
			Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
			return
		}
		Write-Verbose "Found Executable: $SecEdit"
		
		# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
		# names, so use this hashtable
		$UserLogonRights = @{
			"SeAssignPrimaryTokenPrivilege"			    = "Replace a process level token"
			"SeAuditPrivilege"						    = "Generate security audits"
			"SeBackupPrivilege"						    = "Back up files and directories"
			"SeBatchLogonRight"						    = "Log on as a batch job"
			"SeChangeNotifyPrivilege"				    = "Bypass traverse checking"
			"SeCreateGlobalPrivilege"				    = "Create global objects"
			"SeCreatePagefilePrivilege"				    = "Create a pagefile"
			"SeCreatePermanentPrivilege"			    = "Create permanent shared objects"
			"SeCreateSymbolicLinkPrivilege"			    = "Create symbolic links"
			"SeCreateTokenPrivilege"				    = "Create a token object"
			"SeDebugPrivilege"						    = "Debug programs"
			"SeDenyBatchLogonRight"					    = "Deny log on as a batch job"
			"SeDenyInteractiveLogonRight"			    = "Deny log on locally"
			"SeDenyNetworkLogonRight"				    = "Deny access to this computer from the network"
			"SeDenyRemoteInteractiveLogonRight"		    = "Deny log on through Remote Desktop Services"
			"SeDenyServiceLogonRight"				    = "Deny log on as a service"
			"SeEnableDelegationPrivilege"			    = "Enable computer and user accounts to be trusted for delegation"
			"SeImpersonatePrivilege"				    = "Impersonate a client after authentication"
			"SeIncreaseBasePriorityPrivilege"		    = "Increase scheduling priority"
			"SeIncreaseQuotaPrivilege"				    = "Adjust memory quotas for a process"
			"SeIncreaseWorkingSetPrivilege"			    = "Increase a process working set"
			"SeInteractiveLogonRight"				    = "Allow log on locally"
			"SeLoadDriverPrivilege"					    = "Load and unload device drivers"
			"SeLockMemoryPrivilege"					    = "Lock pages in memory"
			"SeMachineAccountPrivilege"				    = "Add workstations to domain"
			"SeManageVolumePrivilege"				    = "Perform volume maintenance tasks"
			"SeNetworkLogonRight"					    = "Access this computer from the network"
			"SeProfileSingleProcessPrivilege"		    = "Profile single process"
			"SeRelabelPrivilege"					    = "Modify an object label"
			"SeRemoteInteractiveLogonRight"			    = "Allow log on through Remote Desktop Services"
			"SeRemoteShutdownPrivilege"				    = "Force shutdown from a remote system"
			"SeRestorePrivilege"					    = "Restore files and directories"
			"SeSecurityPrivilege"					    = "Manage auditing and security log"
			"SeServiceLogonRight"					    = "Log on as a service"
			"SeShutdownPrivilege"					    = "Shut down the system"
			"SeSyncAgentPrivilege"					    = "Synchronize directory service data"
			"SeSystemEnvironmentPrivilege"			    = "Modify firmware environment values"
			"SeSystemProfilePrivilege"				    = "Profile system performance"
			"SeSystemtimePrivilege"					    = "Change the system time"
			"SeTakeOwnershipPrivilege"				    = "Take ownership of files or other objects"
			"SeTcbPrivilege"						    = "Act as part of the operating system"
			"SeTimeZonePrivilege"					    = "Change the time zone"
			"SeTrustedCredManAccessPrivilege"		    = "Access Credential Manager as a trusted caller"
			"SeUndockPrivilege"						    = "Remove computer from docking station"
			"SeDelegateSessionUserImpersonatePrivilege" = "Obtain an impersonation token for another user in the same session"
			"SeSynchronizePrivilege"				    = "Required to use the object wait functions"
			"SePrivilegeNotHeld"					    = "Privilege not held"
		}
		try
		{
			# Attempt to reference the 'Win32.AdvApi32' type to check if it already exists.
			# Casting to [void] suppresses any output or errors if the type doesn't exist.
			[void][Win32.AdvApi32]
		}
		catch
		{
			# If the type does not exist, an exception is thrown and caught here.
			# We proceed to define the type using the Add-Type cmdlet.
			
			# Use Add-Type to define a new .NET type in C# code.
			# The -TypeDefinition parameter accepts a string containing the C# code.
			Add-Type -TypeDefinition @"
    // Include necessary namespaces for the C# code.
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    // Define a namespace called 'Win32' to contain our class.
    namespace Win32
    {
        // Define a public class 'AdvApi32' to hold our P/Invoke method.
        public class AdvApi32
        {
            // Use the DllImport attribute to import the 'LookupPrivilegeDisplayName' function from 'advapi32.dll'.
            // SetLastError = true allows us to retrieve error information if the call fails.
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeDisplayName(
              string systemName,         // The name of the target system (null for local).
              string privilegeName,      // The name of the privilege to look up.
              StringBuilder displayName, // A StringBuilder to receive the privilege's display name.
              ref uint cbDisplayName,    // The size of the displayName buffer; updated with the actual size used.
              out uint languageId        // Receives the language identifier for the returned display name.
            );
        }
    }
"@ -PassThru | Out-Null
			# -PassThru outputs the generated type, but we pipe it to Out-Null to suppress output.
		}
		
		
		# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
		# (except for user logon rights)
		function Get-PrivilegeDisplayName
		{
			param (
				[String]$name # The privilege name to look up
			)
			
			# Create a StringBuilder object to receive the display name of the privilege
			$displayNameSB = New-Object System.Text.StringBuilder 1024
			$languageId = 0
			
			# Call the LookupPrivilegeDisplayName API function to get the display name
			$ok = [Win32.AdvApi32]::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)
			
			# If the API call is successful, return the display name as a string
			if ($ok)
			{
				return $displayNameSB.ToString()
			}
			# If the API call fails, check the hashtable for the privilege name
			else
			{
				# Use an if statement to check if the key exists in the hashtable
				if ($UserLogonRights[$name])
				{
					return $UserLogonRights[$name]
				}
				else
				{
					return $name
				}
			}
		}
		
		
		# Outputs list of hashtables as a PSObject
		function Out-Object
		{
			param (
				[System.Collections.Hashtable[]]$hashData
			)
			$order = @()
			$result = @{ }
			$hashData | ForEach-Object {
				$order += ($_.Keys -as [Array])[0]
				$result += $_
			}
			$out = New-Object PSObject -Property $result | Select-Object $order
			return $out
		}
		# Translates a SID in the form *S-1-5-... to its account name;
		function Get-AccountName
		{
			param (
				[String]$principal
			)
			try
			{
				$sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
				$sid.Translate([Security.Principal.NTAccount])
			}
			catch { $principal }
		}
		$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
		$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
		$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename
		Write-Verbose "$(($StdOut | Out-String).Trim())"
		if ($LASTEXITCODE -eq 0)
		{
			$dtable = $null
			$dtable = New-Object System.Data.DataTable
			$dtable.Columns.Add("Privilege", "System.String") | Out-Null
			$dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
			$dtable.Columns.Add("Principal", "System.String") | Out-Null
			Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
				$Privilege = $_.Matches[0].Groups[1].Value
				$Principals = $_.Matches[0].Groups[2].Value -split ','
				foreach ($Principal in $Principals)
				{
					$PrincipalName = Get-AccountName $Principal
					
					# If $UserName is provided, filter the output
					if (-not $UserName -or ($UserName -contains $PrincipalName))
					{
						$nRow = $dtable.NewRow()
						$nRow.Privilege = $Privilege
						$nRow.PrivilegeName = Get-PrivilegeDisplayName $Privilege
						$nRow.Principal = $PrincipalName
						$dtable.Rows.Add($nRow)
					}
				}
				return $dtable
			}
		}
		else
		{
			$OFS = ""
			Write-Error "$StdOut"
		}
		Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
	}
	try
	{
		Get-SecurityPolicy | Select-Object Privilege, PrivilegeName, Principal -Unique | Sort-Object Privilege | Out-FileWithErrorHandling -FilePath "$miscFolder\UserRightsAssignment.txt" -Width 2048 -Force -ErrorAction Stop
	}
	catch
	{
		Write-Console "$_" -ForegroundColor Red
	}
	
}