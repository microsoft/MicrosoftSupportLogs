<#
.SYNOPSIS
    Generate and collect logs needed to assist Microsoft Support with customer support cases.

.DESCRIPTION
    This script gathers log files and diagnostic information required by Microsoft Support to investigate customer issues. 
    The script collects various logs and outputs them to a folder named C:\MicrosoftSupportLogs_<LocalComputerName>. 
    The collected data is not automatically uploaded. 
    Users must zip the folder and subfolders manually and then upload it to Microsoft Support.

.NOTES
    Created by: Austin Mack
    Modified by: Blake Drumm (blakedrumm@microsoft.com)
    Version: 1.2
    Last Modified: 4 October 2024

    ----------------------------------------------------------------------------
    Change Log
    ----------------------------------------------------------------------------
    October 4th, 2024 - Blake Drumm (blakedrumm@microsoft.com): Fixed spelling errors and incorporated Troubleshoot-WindowsUpdateAgentRegistration (https://www.powershellgallery.com/packages/Troubleshoot-WindowsUpdateAgentRegistration/1.1/Content/Troubleshoot-WindowsUpdateAgentRegistration.ps1) into main script

    ----------------------------------------------------------------------------

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

.EXAMPLE
    Run the script to collect logs:
    .\Collect-SupportLogs.ps1

.INPUTS
    None. You do not need to pipe any input to this script.

.OUTPUTS
    A folder with log files located at C:\MicrosoftSupportLogs, including subfolders.

.LINK
    For additional information, contact Microsoft Support.
#>


$wsid = "########-####-####-####-############" ## workspace ID is available from Log analytics workspace overview page
$aaid = "########-####-####-####-############" ## Automation ID is included in the on the URL field under Keys under the automation account
$location = "####" ##  use link to find abbreviation mapping:  https://docs.microsoft.com/en-us/azure/automation/how-to/automation-region-dns-records#support-for-private-link

$outputFolder = "C:\MicrosoftSupportLogs" ## Script automatically adds the computer name to the end of the path.
##  
##  Update the line above as needed.  
#########################################################################################
$GetUpdateInfo = $true
$version = "4 October 2024"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$CRLF = "rn" ## 13 + 10
if ($location.Length -gt 4)
{
	Write-Verbose -Verbose "$location="$location"  IS WRONG.  Please update and use abbreviated region name and re-run the script using link below"
	Write-Verbose -Verbose ("   https" + "://docs.microsoft.com/en-us/azure/automation/how-to/automation-region-dns-records#support-for-private-link$CRLF")
	Write-Verbose -Verbose 'Should be something like the following if the Automation account is in East US region:    $location="eus"'
	Write-Verbose -Verbose 'Sample abbreviated region names: eus, eus2, san, ea, sea, ac, brs, cc, dewc, ...'
	Break
}
function CheckSSL($fqdn, $port = 443, $tls = "tls12") # Verbose output
{
	Try { $tcpsocket = New-Object Net.Sockets.TcpClient($fqdn, $port) }
	Catch { Write-Warning "$($_.Exception.Message) / $fqdn" }
	$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
	$sslProtocols = [System.Security.Authentication.SslProtocols]::$tls
	""; "-- Target: $fqdn / " + $tcpsocket.Client.RemoteEndPoint.Address.IPAddressToString
	$sslStream = New-Object System.Net.Security.SslStream($tcpsocket.GetStream(), $false)
	$sslStream.AuthenticateAsClient($fqdn, $certCollection, $sslProtocols, $true) ## A Boolean value that specifies whether the certificate revocation list is checked during authentication
	$certinfo = New-Object security.cryptography.x509certificates.x509certificate2($sslStream.RemoteCertificate)
	$sslStream | select-object | Format-List sslProtocol, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus
	$certinfo | Format-List Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
	$certinfo.Extensions | Where-Object { $_.Oid.FriendlyName -like 'subject alt*' } | ForEach-Object { $_.Oid.FriendlyName; $_.Format($true) }
	$tcpsocket.Close()
}

## output DestinationFolder assumes ends with  \
function CopyFile($SourceFile, $DestinationFolder)
{
	if (Test-Path $sourceFile)
	{
		$DateTime = (Get-Date).ToString('yyyy-MMM-dd_HH-MM') ## creates Year-month-date_Hour-Minute and appends to end of file to create a unique file name to prevent file in use
		$Sourcefileinfo = (Get-ChildItem $SourceFile)[0] ## just in case someone did not pass a single file [0]
		$SourcefileName = $Sourcefileinfo.Name
		$SourcefileBaseName = $Sourcefileinfo.BaseName
		$SourceFilePath = $Sourcefileinfo.PSParentPath
		$SourcefileExtension = $Sourcefileinfo.Extension
		
		Copy-Item $sourceFile ($DestinationFolder + $SourcefileBaseName + "_" + $DateTime + $SourcefileExtension)
		$cmd = "copy " + $sourceFile + " " + ($DestinationFolder + $SourcefileBaseName + "_" + $DateTime + $SourcefileExtension)
		Write-Verbose -Verbose $cmd
	}
	else
	{ "'$SourceFile' was not found on computer $($env:COMPUTERNAME). Depending on the system this may be expected" >> ($DestinationFolder + "NotFoundFiles.txt") }
}

Function CreateFolder($path) # Create the entire Folder path if missing
{
	foreach ($SubFolder in $path.split('\'))
	{ $foldPath += ($SubFolder + '\'); if (!(Test-Path $foldPath)) { New-Item -ItemType Directory -Path $foldPath } }
}

function TryCmdlet($command, $outputfileName)
{
	Try
	{
		"== $(Get-Date).tostring()) / $command " *>> $outputfileName
		& $command *>> $outputfileName; "" >> $outputfileName
	}
	Catch { }
}

"== " + (Get-Date).tostring() + " Starting data collection"
$lastChar = $outputFolder.Substring($OutputFolder.Length - 1)
if ($lastChar -eq "\" -or $lastChar -eq "/") { $outputFolder = ($outputFolder.Substring(0, $OutputFolder.Length - 1) + "_" + $env:computerName + "\") }
else { $outputFolder = ($outputFolder + "_" + $env:computerName + "\") }
if (!(Test-Path $outputFolder)) { New-Item -ItemType Directory -Path $outputFolder }
Set-Location $outputFolder

#### net start
$MMA_Folder = $outputFolder + "MMA-Agent\"
$TCPTest = $MMA_Folder + "TCP_Connectivity.txt"
if (!(Test-Path $MMA_Folder)) { New-Item -ItemType Directory -Path $MMA_Folder }
if (Test-Path "C:\Program Files\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe")
{
	&"C:\Program Files\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe" *> ($MMA_Folder + "TestCloudConnection.txt")
	$testCloudConnection = Get-Content ($MMA_Folder + "TestCloudConnection.txt") | Where-Object{ if ($_.ToString().Length -gt 1) { $_.ToString().Substring($_.ToString().Length - 1, 1) -ne "." } }
	[string]$TestTargetstr = $testCloudConnection | select-string ".agentsvc.azure-automation.net" | select-string -NotMatch 'Firewall Rule:'
	[string]$TestTargetstr += " " + ($testCloudConnection | select-string ".ods.opinsights.azure.com" | select-string -NotMatch 'Firewall Rule:')
	[string]$TestTargetstr += (" " + ($testCloudConnection | select-string ".oms.opinsights.azure.com" | select-string -NotMatch 'Firewall Rule:')).replace('Making initial connection to', "")
	[string]$TestTargetstr += " " + ($testCloudConnection | select-string ".blob.core.windows.net" | select-string -NotMatch 'Firewall Rule:')
	[Array]$TestTargetarr = (($TestTargetstr.Split(' ')).Split($tab))
	$TestTargetarr = $TestTargetarr | Sort-Object -Unique | select-object -skip 1
}
if (($wsid -notlike "*####*") -and ("$wsid.oms.opinsights.azure.com") -notin $TestTargetarr)
{
	[Array]$TestTargetarr += "$wsid.ods.opinsights.azure.com";
	[Array]$TestTargetarr += "$wsid.oms.opinsights.azure.com";
	[Array]$TestTargetarr += "$wsid.agentsvc.azure-automation.net";
	[Array]$TestTargetarr += "scadvisorcontent.blob.core.windows.net";
}
$TestTargetarr = $TestTargetarr | Sort-Object -Unique

$result = $null
$NetworkFolder = $outputFolder + "Network\"
If (!(Test-Path $NetworkFolder)) { New-Item -ItemType Directory -Path $NetworkFolder }
"Local Time: " + (Get-Date).tostring() + "    Universal Time: " + (Get-Date).ToUniversalTime() + $CRLF *> ($NetworkFolder + "CheckSSL.txt")
foreach ($TargetEndpoint in $TestTargetarr)
{
	[Array]$result += Test-NetConnection $TargetEndpoint -port 443
	CheckSSL $TargetEndpoint *>> ($NetworkFolder + "CheckSSL.txt")
}
$result | Format-Table -AutoSize > $TCPTest

[Array]$MiscTargetarr = "login.windows.net"
[Array]$MiscTargetarr += "management.core.windows.net"
$MiscTargetarr += "catalog.update.microsoft.com"
$MiscTargetarr += "agentserviceapi.guestconfiguration.azure.com";
$MiscTargetarr += "gbl.his.arc.azure.com"
$MiscTargetarr += "api.monitor.azure.com";
$MiscTargetarr += "profiler.monitor.azure.com";
$MiscTargetarr += "live.monitor.azure.com";
$MiscTargetarr += "snapshot.monitor.azure.com";

$result = $null
foreach ($MiscTargetEndPoint in $MiscTargetarr) { [Array]$result += Test-NetConnection $MiscTargetEndPoint -port 443 }
$result | Format-Table -AutoSize >> $TCPTest

$jrdsArr = @()
$regpath = "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker"
If (Test-Path $regpath)
{
	Get-ChildItem -Path $regpath -Recurse | ForEach-Object {
		$props = Get-ItemProperty -Path $_.PSPath
		if ($props.JobRuntimeDataServiceUri) { $jrdsArr = $jrdsArr + $props.JobRuntimeDataServiceUri }
	}
}
$regpath = "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2"
If (Test-Path $regpath)
{
	Get-ChildItem -Path $regpath -Recurse | ForEach-Object {
		$props = Get-ItemProperty -Path $_.PSPath
		if ($props.JobRuntimeDataServiceUri) { $jrdsArr = $jrdsArr + $props.JobRuntimeDataServiceUri }
	}
}
$jrdsArr = $jrdsArr.Replace('https://', '')
$jrdsArr = $jrdsArr | Sort-Object -Unique
$aaidArr = @()
Foreach ($endpoint in $jrdsArr)
{
	if ($endpoint.length -gt 63) ##  there is legacy URL that is shorter that does not have the following format  "https://########-####-####-####-############.jrds.eus2.azure-automation.net"
	{
		$EndpointAaid = $endpoint.Split(".")[0]
		$EndpointLocation = $endpoint.Split(".")[2]
		CheckSSL "$EndpointAaid.jrds.$EndpointLocation.azure-automation.net"  *>> ($NetworkFolder + "CheckSSL.txt")
		CheckSSL "$EndpointAaid.agentsvc.$EndpointLocation.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
		CheckSSL "$EndpointAaid.webhook.$EndpointLocation.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
		CheckSSL "$EndpointLocation-jobruntimedata-prod-su1.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
	}
	else { CheckSSL $endpoint *>> ($NetworkFolder + "CheckSSL.txt") } ## possibly old endpoint format:   eus2-jobruntimedata-prod-su1.azure-automation.net
}

if (($aaid -notlike "*####*") -and ($aaid -notin $jrdsArr))
{
	CheckSSL "$aaid.jrds.$location.azure-automation.net"  *>> ($NetworkFolder + "CheckSSL.txt")
	CheckSSL "$aaid.agentsvc.$location.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
	CheckSSL "$aaid.webhook.$location.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
	CheckSSL "$location-jobruntimedata-prod-su1.azure-automation.net" *>> ($NetworkFolder + "CheckSSL.txt")
}

$result = $null
foreach ($MiscTargetEndPoint in $MiscTargetarr) { CheckSSL $MiscTargetEndPoint *>> ($NetworkFolder + "CheckSSL.txt") }
$result | Format-Table -AutoSize >> $TCPTest
#### Net end

$result = $null; $CheckSSLSummary = ($NetworkFolder + "CheckSSLSummary.txt")
"Local Time: " + (Get-Date).tostring() + "    Universal Time: " + (Get-Date).ToUniversalTime() + $CRLF *> $CheckSSLSummary
$result = Get-Content ($NetworkFolder + "CheckSSL.txt") | select-string @("Exception", "-- Target", "Issuer")
ForEach ($line in $result)
{
	if ($line.ToString() -like "-- Target*")
	{
		if ($line.ToString().IndexOf("jrds") -gt 0) { "$CRLF" *>> $CheckSSLSummary }
		if ($line.ToString().IndexOf("login") -gt 0) { "$CRLF" *>> $CheckSSLSummary }
		$crlf + $line.ToString() *>> $CheckSSLSummary
	}
	else { $line.ToString() *>> $CheckSSLSummary }
}


$OutputDHCPOPtions = $NetworkFolder + "DHCP-Options.txt"
################################################################
function Convert-ByteArrayToString
{
	################################################################
	# Returns the string representation of a System.Byte[] array.
	# ASCII string is the default
	# Encoding of the string: ASCII, Unicode, UTF7, UTF8 or UTF32.
	################################################################
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, ValueFromPipeline = $True)]
		[System.Byte[]]$ByteArray,
		[Parameter()]
		[String]$Encoding = "ASCII"
	)
	switch ($Encoding.ToUpper())
	{
		"ASCII" { $EncodingType = "System.Text.ASCIIEncoding" }
		"UNICODE" { $EncodingType = "System.Text.UnicodeEncoding" }
		"UTF7" { $EncodingType = "System.Text.UTF7Encoding" }
		"UTF8" { $EncodingType = "System.Text.UTF8Encoding" }
		"UTF32" { $EncodingType = "System.Text.UTF32Encoding" }
		Default { $EncodingType = "System.Text.ASCIIEncoding" }
	}
	$Encode = new-object $EncodingType
	$Encode.GetString($ByteArray)
}
# "DHCP Message Type 53 values" from http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
$DhcpMessageType53Values += @("")
$DhcpMessageType53Values += @("DHCPDISCOVER")
$DhcpMessageType53Values += @("DHCPOFFER")
$DhcpMessageType53Values += @("DHCPREQUEST")
$DhcpMessageType53Values += @("DHCPDECLINE")
$DhcpMessageType53Values += @("DHCPACK")
$DhcpMessageType53Values += @("DHCPNAK")
$DhcpMessageType53Values += @("DHCPRELEASE")
$DhcpMessageType53Values += @("DHCPINFORM")
$DhcpMessageType53Values += @("DHCPFORCERENEW")
$DhcpMessageType53Values += @("DHCPLEASEQUERY")
$DhcpMessageType53Values += @("DHCPLEASEUNASSIGNED")
$DhcpMessageType53Values += @("DHCPLEASEUNKNOWN")
$DhcpMessageType53Values += @("DHCPLEASEACTIVE")
$DhcpMessageType53Values += @("DHCPBULKLEASEQUERY")
$DhcpMessageType53Values += @("DHCPLEASEQUERYDONE")
# Iterate through NIC's with IP obtained via DHCP  
# HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{########-####-####-####-############}
$objWin32NAC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -namespace "root\CIMV2" -computername "." -Filter "IPEnabled = 'True' AND DHCPEnabled ='True'"
"Computer=$($env:ComputerName)    local Time:" + (Get-Date).ToString() + "    UTC Time: " + (Get-Date).ToUniversalTime()  > $OutputDHCPOPtions
""  >> $OutputDHCPOPtions
" if present display network Adapters using Get-WmiObject -Class Win32_NetworkAdapterConfiguration that have IPEnabled=True and DHCPEnabled=true"  >> $OutputDHCPOPtions
""  >> $OutputDHCPOPtions

foreach ($objNACItem in $objWin32NAC)
{
	"Reading DHCP options of NIC: " + $objNACItem.Caption
	"Reading DHCP options of NIC: " + $objNACItem.Caption  >> $OutputDHCPOPtions
	"  IP address : " + ((Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpIPAddress).DhcpIPAddress)  >> $OutputDHCPOPtions
	"  DHCP server: " + ((Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpServer).DhcpServer)  >> $OutputDHCPOPtions
	"  Options    : "   >> $OutputDHCPOPtions
	#Read DHCP options
	$DhcpInterfaceOptions = (Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpInterfaceOptions).DhcpInterfaceOptions
	$DhcpOptions = @(); for ($i = 0; $i -lt 256; $i++) { $DhcpOptions += @("") }
	$DhcpVendorSpecificOptions = @(); for ($i = 0; $i -lt 256; $i++) { $DhcpVendorSpecificOptions += @("") }
	#Iterate through DHCP options
	$intPosition = 0
	while ($intPosition -lt $DhcpInterfaceOptions.length)
	{
		#Read Dhcp code 
		$DhcpOptionCode = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 8 #shift 8 bytes
		#Read length
		$DhcpOptionLength = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 4 #shift 4 bytes
		#Is this a vendor specific option?
		$DhcpIsVendorSpecific = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 4 #shift 4 bytes
		#Read "unknown data"
		$DhcpUnknownData = ""
		for ($i = 0; $i -lt 4; $i++) { $DhcpUnknownData = $DhcpUnknownData + $DhcpInterfaceOptions[$intPosition + $i] }
		$intPosition = $intPosition + 4 #shift 4 bytes
		#Read value
		if (($DhcpOptionLength % 4) -eq 0) { $DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4)) }
		else { $DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4) + 4) }
		$DhcpOptionValue = New-Object Byte[] $DhcpOptionBytesToRead
		for ($i = 0; $i -lt $DhcpOptionLength; $i++) { $DhcpOptionValue[$i] = $DhcpInterfaceOptions[$intPosition + $i] }
		$intPosition = $intPosition + $DhcpOptionBytesToRead #shift the number of bytes read
		#Add option to (vendor specific) array
		if ($DhcpIsVendorSpecific -eq 0)
		{
			$DhcpOptions[$DhcpOptionCode] = $DhcpOptionValue
		}
		else
		{
			$DhcpVendorSpecificOptions[$DhcpOptionCode] = $DhcpOptionValue
		}
	}
	#Show Dhcp Options
	for ($i = 0; $i -lt 256; $i++)
	{
		#Is this option 43 (vendor specific)?
		if ($i -ne 43)
		{
			$DhcpOptionIndex = $i
			$DhcpOptionValue = $DhcpOptions[$DhcpOptionIndex]
			
			if ($DhcpOptionValue)
			{
				$dhcpOptionName = ($dhcpOptionDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Name; if (-not [string]::IsNullOrEmpty($dhcpOptionName)) { $dhcpOptionName = (" ({0})" -f $dhcpOptionName) }
				$dhcpOptionType = ($dhcpOptionDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Type; if ([string]::IsNullOrEmpty($dhcpOptionType)) { $dhcpOptionType = "unknown" }
				
				switch ($dhcpOptionType.ToLower())
				{
					"ip"          { "  - $DhcpOptionIndex $dhcpOptionName : $($DhcpOptionValue[0]).$($DhcpOptionValue[1]).$($DhcpOptionValue[2]).$($DhcpOptionValue[3]).$($DhcpOptionValue[4])." >> $OutputDHCPOPtions }
					"string"      { "  - $DhcpOptionIndex $dhcpOptionName : $(Convert-ByteArrayToString $DhcpOptionValue)" >> $OutputDHCPOPtions }
					"time"        { "  - $DhcpOptionIndex $dhcpOptionName : $([Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16)) seconds" >> $OutputDHCPOPtions }
					"dhcpmsgtype" { "  - $DhcpOptionIndex $dhcpOptionName : $($DhcpOptionValue[0]) $($DhcpMessageType53Values[$DhcpOptionValue[0]])" >> $OutputDHCPOPtions }
					default       { "  - $DhcpOptionIndex $dhcpOptionName : " + $($DhcpOptionValue | ForEach-Object { $_.ToString("X2") })  >> $OutputDHCPOPtions }
				}
			}
		}
		else
		{
			"  - $i (vendor specific)"   >> $OutputDHCPOPtions
			for ($j = 0; $j -lt 256; $j++)
			{
				$DhcpOptionIndex = $j
				$DhcpOptionValue = $DhcpVendorSpecificOptions[$DhcpOptionIndex]
				
				if ($DhcpOptionValue)
				{
					$dhcpOptionName = ($dhcpOptionVSDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Name; if (-not [string]::IsNullOrEmpty($dhcpOptionName)) { $dhcpOptionName = (" ({0})" -f $dhcpOptionName) }
					$dhcpOptionType = ($dhcpOptionVSDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Type; if ([string]::IsNullOrEmpty($dhcpOptionType)) { $dhcpOptionType = "unknown" }
					"$DhcpOptionIndex $dhcpOptionName" >> $OutputDHCPOPtions
					switch ($dhcpOptionType.ToLower())
					{
						"ip"          { "  - $DhcpOptionIndex (vendor specific) : $($DhcpOptionValue[0]).$($DhcpOptionValue[1]).$($DhcpOptionValue[2]).$($DhcpOptionValue[3]).$($DhcpOptionValue[4])." >> $OutputDHCPOPtions }
						"string"      { "  - $DhcpOptionIndex (vendor specific) : $(Convert-ByteArrayToString $DhcpOptionValue)" >> $OutputDHCPOPtions }
						"time"        { "  - $DhcpOptionIndex (vendor specific) : $([Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16)) seconds" >> $OutputDHCPOPtions }
						"dhcpmsgtype" { "  - $DhcpOptionIndex (vendor specific) : $($DhcpOptionValue[0]) $($DhcpMessageType53Values[$DhcpOptionValue[0]])" >> $OutputDHCPOPtions }
						default       { "  - $DhcpOptionIndex (vendor specific) : " + $($DhcpOptionValue | ForEach-Object { $_.ToString("X2") })  >> $OutputDHCPOPtions }
					}
				}
			}
		}
	}
}

$OS_MiscFolder = $outputFolder + "OS-Miscellaneous\"
If (!(Test-Path $OS_MiscFolder)) { New-Item -ItemType Directory -Path $OS_MiscFolder }
$ENVfileoutput = $OS_MiscFolder + "Env.txt"
Get-ChildItem env: *> $ENVfileoutput
"" >> $ENVfileoutput
"# List paths in PSModulePath" >> $ENVfileoutput
($env:PSModulePath).Split(";") | ForEach-Object { $_.Trim() } | ForEach-Object {
	if ($_.LastIndexOfAny("\") -ne ($_.Length - 1)) { $_ + "\" }
	else { $_ }
} >> $ENVfileoutput
"" >> $ENVfileoutput
"# List paths in Path" >> $ENVfileoutput
($env:Path).Split(";") | ForEach-Object { $_.Trim() } | ForEach-Object {
	if ($_.LastIndexOfAny("\") -ne ($_.Length - 1)) { $_ + "\" }
	else { $_ }
} >> $ENVfileoutput

Copy-Item C:\windows\logs\cbs\*.log $OS_MiscFolder
if (Test-Path "c:\windows\WindowsUpdate.log") { Copy-Item c:\windows\WindowsUpdate.log $OS_MiscFolder }

$OS_MiscFolder = $outputFolder + "OS-Miscellaneous\"
$ModuleListFile = $outputFolder + "OS-Miscellaneous\PSModuleList.txt"
"Computer=$($env:ComputerName)    local Time:" + (Get-Date).ToString() + "    UTC Time: " + (Get-Date).ToUniversalTime()  > $ModuleListFile
"" >> $ModuleListFile
"" + (Get-Date).tostring() + " - Checking PowerShell Modules"
"== Modules loaded in memory, when the script ran" >> $ModuleListFile
get-module >> $ModuleListFile
"" >> $ModuleListFile
"== List of available modules" >> $ModuleListFile
$PSModules = Get-Module -listavailable
$PSModules | Format-Table Name, version, CompatiblePSEditions, DotNetFrameworkVersion >> $ModuleListFile

if (Test-Path 'Cert:\LocalMachine\Microsoft Monitoring Agent') { Get-ChildItem 'Cert:\LocalMachine\Microsoft Monitoring Agent' *> ($MMA_Folder + "MMA_Cert.txt") }
else
{ "'Cert:\LocalMachine\Microsoft Monitoring Agent' was NOT FOUND. If MMA (Microsoft Monitoring Agent) is not installed it is ok if the Certificate folder is not found." *> ($MMA_Folder + "MMA_Cert.txt") }

$ProxyFolder = $outputFolder + "ProxyStuff\"
If (!(Test-Path $ProxyFolder)) { New-Item -ItemType Directory -Path $ProxyFolder }
$OutputFile = ($ProxyFolder + "Win-HTTP-Proxy.txt")
netsh Winhttp show proxy  *> $OutputFile
"Note Proxy can be set through DHCP Option 252 see $($networkFolder + "DHCP-Options.txt") for more details"  > ($ProxyFolder + "DHCP-Proxy.txt")

# Troubleshoot-WindowsUpdateAgentRegistration
function Troubleshoot-WindowsUpdateAgentRegistration
{
    <#PSScriptInfo
 
    .VERSION 1.1
 
    .GUID fa3f8397-9d89-4f06-985c-2dfffcfd5520
 
    .AUTHOR Stas Kuvshinov, Swapnil Jain
 
    .COMPANYNAME Microsoft Corporation
 
    .COPYRIGHT © 2020 Microsoft Corporation. All rights reserved.
 
    .TAGS Automation UpdateManagement HybridRunbookWorker Troubleshoot
 
    .LICENSEURI
 
    .PROJECTURI
 
    .ICONURI
 
    .EXTERNALMODULEDEPENDENCIES
 
    .REQUIREDSCRIPTS
 
    .EXTERNALSCRIPTDEPENDENCIES
 
    .RELEASENOTES
    1.1 Added rules: AlwaysAutoRebootCheck, WSUSServerConfigured, AutomaticUpdateCheck
    1.0 Original set of troubleshooting checks for Update Management Agent (Automation Hybrid Runbook Worker) on Windows machines
 
    .PRIVATEDATA
 
    #>
	
    <#
 
    .DESCRIPTION
     Troubleshooting utility for Update Management Agent (Automation Hybrid Runbook Worker) on Windows machines
 
    #>	
	param (
		[string]$automationAccountLocation,
		[switch]$returnCompactFormat,
		[switch]$returnAsJson
	)
	
	$validationResults = @()
	[string]$CurrentResult = ""
	[string]$CurrentDetails = ""
	function New-RuleCheckResult
	{
		[CmdletBinding()]
		param (
			[string][Parameter(Mandatory = $true)]
			$ruleId,
			[string]$ruleName,
			[string]$ruleDescription,
			[string][ValidateSet("Passed", "PassedWithWarning", "Failed", "Information")]
			$result,
			[string]$resultMessage,
			[string]$ruleGroupId = $ruleId,
			[string]$ruleGroupName,
			[string]$resultMessageId = $ruleId,
			[array]$resultMessageArguments = @()
		)
		
		if ($returnCompactFormat.IsPresent)
		{
			$compactResult = [pscustomobject][ordered] @{
				'RuleId'					  = $ruleId
				'RuleGroupId'				  = $ruleGroupId
				'CheckResult'				  = $result
				'CheckResultMessageId'	      = $resultMessageId
				'CheckResultMessageArguments' = $resultMessageArguments
			}
			return $compactResult
		}
		
		$fullResult = [pscustomobject][ordered] @{
			'RuleId'					  = $ruleId
			'RuleGroupId'				  = $ruleGroupId
			'RuleName'				      = $ruleName
			'RuleGroupName'			      = $ruleGroupName
			'RuleDescription'			  = $ruleDescription
			'CheckResult'				  = $result
			'CheckResultMessage'		  = $resultMessage
			'CheckResultMessageId'	      = $resultMessageId
			'CheckResultMessageArguments' = $resultMessageArguments
		}
		return $fullResult
	}
	
	function checkRegValue
	{
		[CmdletBinding()]
		param (
			[string][Parameter(Mandatory = $true)]
			$path,
			[string][Parameter(Mandatory = $true)]
			$name,
			[int][Parameter(Mandatory = $true)]
			$valueToCheck
		)
		
		$val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
		if ($val.$name -eq $null)
		{
			return $null
		}
		
		if ($val.$name -eq $valueToCheck)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	
	function getRegValue
	{
		[CmdletBinding()]
		param (
			[string][Parameter(Mandatory = $true)]
			$path,
			[string][Parameter(Mandatory = $true)]
			$name
		)
		
		$val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
		if ($val.$name -eq $null)
		{
			return $null
		}
		return $val.$name
	}
	
	function Validate-OperatingSystem
	{
		$osRequirementsLink = "https://docs.microsoft.com/azure/automation/automation-update-management#supported-client-types"
		
		$ruleId = "OperatingSystemCheck"
		$ruleName = "Operating System"
		$ruleDescription = "The Windows Operating system must be version 6.1.7601 (Windows Server 2008 R2 SP1) or higher"
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "prerequisites"
		$ruleGroupName = "Prerequisite Checks"
		$resultMessageArguments = @()
		
		if ([System.Environment]::OSVersion.Version -ge [System.Version]"6.1.7601")
		{
			$result = "Passed"
			$resultMessage = "Operating System version is supported"
		}
		else
		{
			$result = "Failed"
			$resultMessage = "Operating System version is not supported. Supported versions listed here: $osRequirementsLink"
			$resultMessageArguments += $osRequirementsLink
		}
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-NetFrameworkInstalled
	{
		$netFrameworkDownloadLink = "https://www.microsoft.com/net/download/dotnet-framework-runtime"
		
		$ruleId = "DotNetFrameworkInstalledCheck"
		$ruleName = ".Net Framework 4.5+"
		$ruleDescription = ".NET Framework version 4.5 or higher is required"
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "prerequisites"
		$ruleGroupName = "Prerequisite Checks"
		$resultMessageArguments = @()
		
		# https://docs.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
		$dotNetFullRegistryPath = "HKLM:SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"
		if ((Get-ChildItem $dotNetFullRegistryPath -ErrorAction SilentlyContinue) -ne $null)
		{
			$versionCheck = (Get-ChildItem $dotNetFullRegistryPath) | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 378389 }
			if ($versionCheck -eq $true)
			{
				$result = "Passed"
				$resultMessage = ".NET Framework version 4.5+ is found"
			}
			else
			{
				$result = "Failed"
				$resultMessage = ".NET Framework version 4.5 or higher is required: $netFrameworkDownloadLink"
				$resultMessageArguments += $netFrameworkDownloadLink
			}
		}
		else
		{
			$result = "Failed"
			$resultMessage = ".NET Framework version 4.5 or higher is required: $netFrameworkDownloadLink"
			$resultMessageArguments += $netFrameworkDownloadLink
		}
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-WmfInstalled
	{
		$wmfDownloadLink = "https://www.microsoft.com/download/details.aspx?id=54616"
		$ruleId = "WindowsManagementFrameworkInstalledCheck"
		$ruleName = "WMF 5.1"
		$ruleDescription = "Windows Management Framework version 4.0 or higher is required (version 5.1 or higher is preferable)"
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "prerequisites"
		$ruleGroupName = "Prerequisite Checks"
		
		$psVersion = $PSVersionTable.PSVersion
		$resultMessageArguments = @() + $psVersion
		
		if ($psVersion -ge 5.1)
		{
			$result = "Passed"
			$resultMessage = "Detected Windows Management Framework version: $psVersion"
		}
		elseif ($psVersion.Major -ge 4)
		{
			$result = "PassedWithWarning"
			$resultMessage = "Detected Windows Management Framework version: $psVersion. Consider upgrading to version 5.1 or higher for increased reliability: $wmfDownloadLink"
			$resultMessageArguments += $wmfDownloadLink
		}
		else
		{
			$result = "Failed"
			$resultMessage = "Detected Windows Management Framework version: $psVersion. Version 4.0 or higher is required (version 5.1 or higher is preferable): $wmfDownloadLink"
			$resultMessageArguments += $wmfDownloadLink
		}
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-TlsEnabled
	{
		$ruleId = "TlsVersionCheck"
		$ruleName = "TLS 1.2"
		$ruleDescription = "Client and Server connections must support TLS 1.2"
		$result = $null
		$reason = ""
		$resultMessage = $null
		$ruleGroupId = "prerequisites"
		$ruleGroupName = "Prerequisite Checks"
		
		$tls12RegistryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\"
		$serverEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 1
		$ServerNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 0
		$clientEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 1
		$ClientNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 0
		
		$ServerNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 0
		$ServerDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 1
		$ClientNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 0
		$ClientDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 1
		
		if ($validationResults[0].CheckResult -ne "Passed" -and [System.Environment]::OSVersion.Version -ge [System.Version]"6.0.6001")
		{
			$result = "Failed"
			$resultMessageId = "$ruleId.$result"
			$resultMessage = "TLS 1.2 is not enabled by default on the Operating System. Follow the instructions to enable it: https://support.microsoft.com/help/4019276/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows"
		}
		elseif ([System.Environment]::OSVersion.Version -ge [System.Version]"6.1.7601" -and [System.Environment]::OSVersion.Version -le [System.Version]"6.1.8400")
		{
			if ($ClientNotDisabled -and $ServerNotDisabled -and !($ServerNotEnabled -and $ClientNotEnabled))
			{
				$result = "Passed"
				$resultMessage = "TLS 1.2 is enabled on the Operating System."
				$resultMessageId = "$ruleId.$result"
			}
			else
			{
				$result = "Failed"
				$reason = "NotExplicitlyEnabled"
				$resultMessageId = "$ruleId.$result.$reason"
				$resultMessage = "TLS 1.2 is not enabled by default on the Operating System. Follow the instructions to enable it: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12"
			}
		}
		elseif ([System.Environment]::OSVersion.Version -ge [System.Version]"6.2.9200")
		{
			if ($ClientDisabled -or $ServerDisabled -or $ServerNotEnabled -or $ClientNotEnabled)
			{
				$result = "Failed"
				$reason = "ExplicitlyDisabled"
				$resultMessageId = "$ruleId.$result.$reason"
				$resultMessage = "TLS 1.2 is supported by the Operating System, but currently disabled. Follow the instructions to re-enable: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12"
			}
			else
			{
				$result = "Passed"
				$reason = "EnabledByDefault"
				$resultMessageId = "$ruleId.$result.$reason"
				$resultMessage = "TLS 1.2 is enabled by default on the Operating System."
			}
		}
		else
		{
			$result = "Failed"
			$reason = "NoDefaultSupport"
			$resultMessageId = "$ruleId.$result.$reason"
			$resultMessage = "Your OS does not support TLS 1.2 by default."
		}
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId
	}
	
	function Validate-EndpointConnectivity
	{
		[CmdletBinding()]
		param (
			[string][Parameter(Mandatory = $true)]
			$endpoint,
			[string][Parameter(Mandatory = $true)]
			$ruleId,
			[string][Parameter(Mandatory = $true)]
			$ruleName,
			[string]$ruleDescription = "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with $endpoint"
		)
		
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "connectivity"
		$ruleGroupName = "connectivity"
		$resultMessageArguments = @() + $endpoint
		
		if ((Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded)
		{
			$result = "Passed"
			$resultMessage = "TCP Test for $endpoint (port 443) succeeded"
		}
		else
		{
			$result = "Failed"
			$resultMessage = "TCP Test for $endpoint (port 443) failed"
		}
		
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-RegistrationEndpointsConnectivity
	{
		$validationResults = @()
		
		$managementGroupRegistrations = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HealthService\\Parameters\\Management Groups' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
		$managementGroupRegistrations | ForEach-Object { $i = 1 } {
			$prefix = "AOI-"
			if ($_ -match "$prefix*")
			{
				$workspaceId = $_.Substring($prefix.Length)
				if ($automationAccountLocation -eq "usgovvirginia" -or $automationAccountLocation -eq "usgovarizona")
				{
					$endpoint = "$workspaceId.agentsvc.azure-automation.us"
				}
				elseif ($automationAccountLocation -eq "chinaeast2")
				{
					$endpoint = "$workspaceId.agentsvc.azure-automation.cn"
				}
				else
				{
					$endpoint = "$workspaceId.agentsvc.azure-automation.net"
				}
				$ruleId = "AutomationAgentServiceConnectivityCheck$i"
				$ruleName = "Registration endpoint"
				
				$validationResults += Validate-EndpointConnectivity $endpoint $ruleId $ruleName
				
				$i++
			}
		}
		
		if ($validationResults.Count -eq 0)
		{
			$ruleId = "AutomationAgentServiceConnectivityCheck1"
			$ruleName = "Registration endpoint"
			
			$result = "Failed"
			$reason = "NoRegistrationFound"
			$resultMessage = "Unable to find Workspace registration information in registry"
			
			$ruleGroupId = "connectivity"
			$ruleGroupName = "connectivity"
			$resultMessageId = "$ruleId.$result.$reason"
			
			$validationResults += New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId
		}
		
		return $validationResults
	}
	
	function Validate-OperationsEndpointConnectivity
	{
		# https://docs.microsoft.com/azure/automation/automation-hybrid-runbook-worker#hybrid-worker-role
		if ($automationAccountLocation -eq "usgovvirginia")
		{
			$endpoint = "usge-jobruntimedata-prod-su1.azure-automation.us"
		}
		elseif ($automationAccountLocation -eq "usgovarizona")
		{
			$endpoint = "phx-jobruntimedata-prod-su1.azure-automation.us"
		}
		elseif ($automationAccountLocation -eq "chinaeast2")
		{
			$endpoint = "sha2-jobruntimedata-prod-su1.azure-automation.cn"
		}
		else
		{
			$jrdsEndpointLocationMoniker = switch ($automationAccountLocation)
			{
				"australiasoutheast"{ "ase" }
				"canadacentral"     { "cc" }
				"centralindia"      { "cid" }
				"eastus2"           { "eus2" }
				"japaneast"         { "jpe" }
				"northeurope"       { "ne" }
				"southcentralus"    { "scus" }
				"southeastasia"     { "sea" }
				"uksouth"           { "uks" }
				"westcentralus"     { "wcus" }
				"westeurope"        { "we" }
				"westus2"           { "wus2" }
				
				default             { "eus2" }
			}
			$endpoint = "$jrdsEndpointLocationMoniker-jobruntimedata-prod-su1.azure-automation.net"
		}
		$ruleId = "AutomationJobRuntimeDataServiceConnectivityCheck"
		$ruleName = "Operations endpoint"
		
		return Validate-EndpointConnectivity $endpoint $ruleId $ruleName
	}
	
	function Validate-MmaIsRunning
	{
		$mmaServiceName = "HealthService"
		$mmaServiceDisplayName = "Microsoft Monitoring Agent"
		
		$ruleId = "MonitoringAgentServiceRunningCheck"
		$ruleName = "Monitoring Agent service status"
		$ruleDescription = "$mmaServiceName must be running on the machine"
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "servicehealth"
		$ruleGroupName = "VM Service Health Checks"
		$resultMessageArguments = @() + $mmaServiceDisplayName + $mmaServiceName
		
		if (Get-Service -Name $mmaServiceName -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object)
		{
			$result = "Passed"
			$resultMessage = "$mmaServiceDisplayName service ($mmaServiceName) is running"
		}
		else
		{
			$result = "Failed"
			$resultMessage = "$mmaServiceDisplayName service ($mmaServiceName) is not running"
		}
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-MmaEventLogHasNoErrors
	{
		$mmaServiceName = "Microsoft Monitoring Agent"
		$logName = "Operations Manager"
		$eventId = 4502
		
		$ruleId = "MonitoringAgentServiceEventsCheck"
		$ruleName = "Monitoring Agent service events"
		$ruleDescription = "Event Log must not have event 4502 logged in the past 24 hours"
		$result = $null
		$reason = ""
		$resultMessage = $null
		$ruleGroupId = "servicehealth"
		$ruleGroupName = "VM Service Health Checks"
		$resultMessageArguments = @() + $mmaServiceName + $logName + $eventId
		
		$OpsMgrLogExists = [System.Diagnostics.EventLog]::Exists($logName);
		if ($OpsMgrLogExists)
		{
			$event = Get-EventLog -LogName "Operations Manager" -Source "Health Service Modules" -After (Get-Date).AddHours(-24) | Where-Object { $_.eventID -eq $eventId }
			if ($event -eq $null)
			{
				$result = "Passed"
				$resultMessageId = "$ruleId.$result"
				$resultMessage = "$mmaServiceName service Event Log ($logName) does not have event $eventId logged in the last 24 hours."
			}
			else
			{
				$result = "Failed"
				$reason = "EventFound"
				$resultMessageId = "$ruleId.$result.$reason"
				$resultMessage = "$mmaServiceName service Event Log ($logName) has event $eventId logged in the last 24 hours. Look at the results of other checks to troubleshoot the reasons."
			}
		}
		else
		{
			$result = "Failed"
			$reason = "NoLog"
			$resultMessageId = "$ruleId.$result.$reason"
			$resultMessage = "$mmaServiceName service Event Log ($logName) does not exist on the machine"
		}
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-MachineKeysFolderAccess
	{
		$folder = "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys"
		
		$ruleId = "CryptoRsaMachineKeysFolderAccessCheck"
		$ruleName = "Crypto RSA MachineKeys Folder Access"
		$ruleDescription = "SYSTEM account must have WRITE and MODIFY access to '$folder'"
		$result = $null
		$resultMessage = $null
		$ruleGroupId = "permissions"
		$ruleGroupName = "Access Permission Checks"
		$resultMessageArguments = @() + $folder
		
		$User = $env:UserName
		$permission = (Get-Acl $folder).Access | Where-Object { ($_.IdentityReference -match $User) -or ($_.IdentityReference -match "Everyone") } | Select-Object IdentityReference, FileSystemRights
		if ($permission)
		{
			$result = "Passed"
			$resultMessage = "Have permissions to access $folder"
		}
		else
		{
			$result = "Failed"
			$resultMessage = "Missing permissions to access $folder"
		}
		$resultMessageId = "$ruleId.$result"
		
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-AlwaysAutoRebootEnabled
	{
		$ruleId = "AlwaysAutoRebootCheck"
		$ruleName = "AutoReboot"
		$ruleDescription = "Automatic reboot should not be enable as it forces a reboot irrespective of update configuration"
		$result = $null
		$reason = ""
		$resultMessage = $null
		$ruleGroupId = "machineSettings"
		$ruleGroupName = "Machine Override Checks"
		
		$automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
		$rebootEnabledBySchedule = checkRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTime" 1
		$rebootEnabledByDuration = getRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTimeMinutes"
		
		
		if ($rebootEnabledBySchedule -or $rebootEnabledByDuration)
		{
			$result = "PassedWithWarning"
			$reason = "Auto Reboot is enabled on the system and will interfere with Update Management Configuration passed during runs"
			$resultMessage = "Windows Update reboot registry keys are set. This can cause unexpected reboots when installing updates"
		}
		else
		{
			$result = "Passed"
			$resultMessage = "Windows Update reboot registry keys are not set to automatically reboot"
			
		}
		$resultMessageId = "$ruleId.$result"
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-AutomaticUpdateEnabled
	{
		$ruleId = "AutomaticUpdateCheck"
		$ruleName = "AutoUpdate"
		$ruleDescription = "AutoUpdate should not be enabled on the machine"
		$result = $null
		$reason = ""
		$resultMessage = $null
		$ruleGroupId = "machineSettings"
		$ruleGroupName = "Machine Override Checks"
		
		$automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
		$autoUpdateEnabled = checkRegValue ($automaticUpdatePath) "AUOptions" 4
		
		
		if ($autoUpdateEnabled)
		{
			$result = "PassedWithWarning"
			$reason = "Auto Update is enabled on the machine and will interfere with Update management Solution"
			$resultMessage = "Windows Update will automatically download and install new updates as they become available"
		}
		else
		{
			$result = "Passed"
			$resultMessage = "Windows Update is not set to automatically install updates as they become available"
			
		}
		$resultMessageId = "$ruleId.$result"
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	function Validate-WSUSServerConfigured
	{
		$ruleId = "WSUSServerConfigured"
		$ruleName = "isWSUSServerConfigured"
		$ruleDescription = "Increase awareness on WSUS configured on the server"
		$result = $null
		$reason = ""
		$resultMessage = $null
		$ruleGroupId = "machineSettings"
		$ruleGroupName = "Machine Override Checks"
		
		$automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
		$wsusServerConfigured = getRegValue ($automaticUpdatePath) "WUServer"
		
		if ($null -ne $wsusServerConfigured)
		{
			$result = "PassedWithWarning"
			$reason = "WSUS Server is configured on the server"
			$resultMessage = "Windows Updates are downloading from a configured WSUS Server $wsusServerConfigured. Ensure the WSUS server is accessible and updates are being approved for installation"
			$resultMessageArguments = @() + $wsusServerConfigured
		}
		else
		{
			$result = "Passed"
			$resultMessage = "Windows Updates are downloading from the default Windows Update location. Ensure the server has access to the Windows Update service"
		}
		$resultMessageId = "$ruleId.$result"
		return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
	}
	
	$validationResults += Validate-OperatingSystem
	$validationResults += Validate-NetFrameworkInstalled
	$validationResults += Validate-WmfInstalled
	Validate-RegistrationEndpointsConnectivity | ForEach-Object { $validationResults += $_ }
	$validationResults += Validate-OperationsEndpointConnectivity
	$validationResults += Validate-MmaIsRunning
	$validationResults += Validate-MmaEventLogHasNoErrors
	$validationResults += Validate-MachineKeysFolderAccess
	$validationResults += Validate-TlsEnabled
	$validationResults += Validate-AlwaysAutoRebootEnabled
	$validationResults += Validate-WSUSServerConfigured
	$validationResults += Validate-AutomaticUpdateEnabled
	
	if ($returnAsJson.IsPresent)
	{
		return ConvertTo-Json $validationResults -Compress
	}
	else
	{
		return $validationResults
	}
}
$TShootWinUpdateAgent = Troubleshoot-WindowsUpdateAgentRegistration
$UMv1Folder = $outputFolder + "Hybrid\"
if (!(Test-Path $UMv1Folder)) { New-Item -ItemType Directory -Path $UMv1Folder }
$outputFileName = "$UMv1Folder" + "Troubleshoot-WindowsUpdateAgentRegistration-output.txt"
$TShootWinUpdateAgent | Format-Table RuleId, CheckResult, CheckResultMessage > $outputFileName
$TShootWinUpdateAgent | Format-List * >> $outputFileName

$eventLogFolder = $outputFolder + "EventLogs\"
if (!(Test-Path $outputFolder)) { New-Item -ItemType Directory -Path $outputFolder }
if (!(Test-Path $eventLogFolder)) { New-Item -ItemType Directory -Path $eventLogFolder }
if ($outputFolder -ne "" -and (Test-Path ("$outputFolder\*.evtx"))) { Remove-Item ("$outputFolder\*.evtx") }
if ($outputFolder -ne "" -and (Test-Path ("$eventLogFolder\*.evtx"))) { Remove-Item ("$eventLogFolder\*.evtx") }
CopyFile C:\Windows\System32\winevt\Logs\Application.evtx $eventLogFolder
CopyFile C:\Windows\System32\winevt\Logs\Setup.evtx $eventLogFolder
CopyFile C:\Windows\System32\winevt\Logs\System.evtx $eventLogFolder
CopyFile "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" $eventLogFolder
CopyFile C:\Windows\System32\winevt\Logs\Microsoft-SMA%4Operational.evtx $eventLogFolder
CopyFile C:\Windows\System32\winevt\Logs\Microsoft-Automation%4Operational.evtx $eventLogFolder
CopyFile C:\Windows\System32\winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx $eventLogFolder
CopyFile "C:\Windows\System32\winevt\Logs\Operations Manager.evtx" $eventLogFolder
CopyFile "C:\Windows\System32\winevt\Logs\OMS Gateway Log.evtx" $eventLogFolder

Copy-Item C:\Windows\System32\drivers\etc\hosts ($NetworkFolder + "\hosts.txt")

$OutputFile = ($OS_MiscFolder + "RSA-MachineKeys_Permissions.txt")
"Local Time: " + (Get-Date).tostring() + "    Universal Time: " + (Get-Date).ToUniversalTime() + $CRLF *> $OutputFile
"Use this file if you get an error similar to:  Could not create SSL/TLS secure channel " *>> $OutputFile
"to confirm $path and the subfiles have the correct permissions $CRLF " *>> $OutputFile
$path = (Get-Item -path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys").FullName
"$crlf $crlf $crlf Folder: $($path)"
"$crlf $crlf $crlf Folder: $($path)"  *>> $OutputFile
(get-acl -path $path).Access
(get-acl -path $path).Access  *>> $OutputFile
$Subfolders = Get-ChildItem -path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
ForEach ($sub in $Subfolders)
{
	$acl = (get-acl -path $Sub.FullName).Access
	if ($acl.IdentityReference[0] -eq "NT AUTHORITY\SYSTEM")
	{
		Write-Output "File: $($Sub.Name) User: $($acl.IdentityReference[0]) Perms: $($acl.FileSystemRights[0])"
		Write-Output "File: $($Sub.Name) User: $($acl.IdentityReference[0]) Perms: $($acl.FileSystemRights[0])"  *>> $OutputFile
	}
}

if (Test-Path "C:\Program Files\Microsoft Monitoring Agent")
{
	"" + (Get-Date).tostring() + " - Listing Microsoft Monitoring Agent files"
	$OutputFile = ($MMA_Folder + "Microsoft-Monitoring-Agent_Dir.txt")
	Get-ChildItem 'C:\Program Files\Microsoft Monitoring Agent' -recurse > $OutputFile
}
else { "'C:\Program Files\Microsoft Monitoring Agent'  folder was not found.  This may be expected if system does not have MMA" >> ($outputFolder + "NotFoundFiles.txt") }

"" + (Get-Date).tostring() + " - Getting Service information"
$servicestxt = $OS_MiscFolder + "services.txt"
Try
{
	"== Summary of a few services at UTC time: " + (Get-Date).ToUniversalTime() *> $servicesTxt
	get-service healthservic*, HybridWorker*, ExtensionServi*, GCArcServi*, himd*, *gateway | Sort-Object DisplayName | Format-Table -autosize *>> $servicesTxt
	"== All service details" *>> $servicesTxt
	Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, ExitCode, StartName, Pathname, ServiceType, StartMode *>> $servicesTxt
}
Catch { }

Try
{
	"== How accurate is the customers time at UTC time: " + (Get-Date).ToUniversalTime() *> ($outputFolder + "WindowsTime.txt")
	"== If the time is off by several minutes it can cause authentication issues  $CRLF" *>> ($outputFolder + "WindowsTime.txt")
	w32tm /stripchart /computer:time.windows.com /samples:4 *>> ($outputFolder + "WindowsTime.txt")
}
Catch { }

ipconfig.exe /all *>> ($NetworkFolder + "ipconfig.txt")

$GPresult = ($OS_MiscFolder + "gpresult.txt")
"" + (Get-Date).tostring() + " - Running:  GPresult"
("Local Time: " + (Get-Date).tostring() + "    Universal Time: " + (Get-Date).ToUniversalTime() + $CRLF) > $GPresult
gpresult /z >> $GPresult

"" + (Get-Date).tostring() + " - Getting Hybrid Worker registry"


$RegoutputFile = ($UMv1Folder + "Reg-HybridRunbookWorker.txt")
if (Test-Path "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker") { REG EXPORT "HKLM\SOFTWARE\Microsoft\HybridRunbookWorker" $RegoutputFile /y }
else
{ "'HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker' Not present" > $RegoutputFile }

$RegoutputFile = ($UMv1Folder + "Reg-HybridRunbookWorkerV2.txt")
if (Test-Path "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2") { REG EXPORT "HKLM\SOFTWARE\Microsoft\HybridRunbookWorkerV2" $RegoutputFile /y }
else
{ "'HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2' Not present" > $RegoutputFile }

"" + (Get-Date).tostring() + " - Getting Proxy information"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
reg load HKU\UserHive "C:\Users\Default\NTUSER.DAT"
$RegoutputFile = ($ProxyFolder + "Reg-System-ProxyInfo.txt")
if (Test-Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings") { REG EXPORT "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y }
else
{ "'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile }
reg unload HKU\UserHive
Remove-PSDrive -Name HKU

$RegoutputFile = ($ProxyFolder + "Reg-HKLM-ProxyInfo.txt")
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings") { REG EXPORT "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y }
else
{ "'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile }

$RegoutputFile = ($ProxyFolder + "Reg-HKCU-ProxyInfo.txt")
if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings") { REG EXPORT "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y }
else
{ "'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile }

$RegoutputFile = ($outputFolder + "REG-WindowsUpdate.txt")
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") { REG EXPORT "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" $RegoutputFile /y }
else
{ "'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' Not present" > $RegoutputFile }

$RegoutputFile = ($NetworkFolder + "REG-SCHANNEL.txt")
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL") { REG EXPORT "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $RegoutputFile /y }
else
{ "'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' Not present" > $RegoutputFile }

$RegoutputFile = ($NetworkFolder + "REG-TLS-Misc.txt")
$Msg = "Computer=$($env:ComputerName)    local Time:" + (Get-Date).ToString() + "    UTC Time: " + (Get-Date).ToUniversalTime()
$regpath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
$return = (get-ItemProperty -Path $regpath).SchUseStrongCrypto; if (!($return)) { $Msg = $MSG + $CRLF + "$regpath\SchUseStrongCrypto NotPresent setting a value of 1 may help)" }
else { $Msg = $MSG + $CRLF + "$regpath\SchUseStrongCrypto=$return" }
$return = ""
$regpath = 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319'
$return = (get-ItemProperty -Path $regpath).SchUseStrongCrypto; if (!($return)) { $Msg = $MSG + $CRLF + "$regpath\SchUseStrongCrypto NotPresent setting a value of 1 may help)" }
else { $Msg = $MSG + $CRLF + "$regpath\SchUseStrongCrypto=$return" }
$return = ""
$regpath = 'HKLM:\system\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$return = (get-ItemProperty -Path $regpath).DisableRenegoOnClient; if ($return -eq 1) { $Msg = $MSG + $CRLF + "!!! WARNING !!! $regpath\DisableRenegoOnClient=1 is present, known to cause problems" }
$MSG > $RegoutputFile

"" + (Get-Date).tostring() + " - Checking for OMS Gateway, if Present"

$Misc = $outputFolder + "Misc.txt"
"== " + (Get-Date).tostring() + " - Script last modified on: $version">> $Misc
"$CRLF== " + (Get-Date).tostring() + ' - (Get-CimInstance Win32_OperatingSystem).version   Note:  UM V1 requires this command.  There should be a version displayed on the very next line'  >> $Misc
(Get-CimInstance Win32_OperatingSystem).version >> $Misc
"$CRLF== " + (Get-Date).tostring() + ' - $PSVersionTable'  >> $Misc
$psversiontable >> $Misc
"$CRLF******************************************************************************************************" >> $Misc
"*** Cmdlets below attempted, some of the cmdlets may not be appropriate and so may not have output ***$CRLF" >> $Misc
Try { "== $(Get-Date).tostring()) /get-module OmsGateway" *>> $Misc; get-module OmsGateway *>> $Misc }
Catch { }
TryCmdlet Get-ForwarderServiceAllowedClientCertificate $Misc
TryCmdlet Get-ForwarderServiceConfig $Misc
TryCmdlet Get-ForwarderServiceRelayProxy $Misc
TryCmdlet Get-OMSGatewayAllowedClientCertificate $Misc
TryCmdlet Get-OMSGatewayAllowedHost $Misc
TryCmdlet Get-OMSGatewayConfig $Misc
TryCmdlet Get-OMSGatewayRelayProxy $Misc
TryCmdlet Get-Process ($OS_MiscFolder + "Get-Process.txt")
"done" + (Get-Date).tostring()

$WinUpdateSettings = $outputFolder + "Windows_Update_Settings.txt"
"Computer=$($env:ComputerName)    local Time:" + (Get-Date).ToString() + "    UTC Time: " + (Get-Date).ToUniversalTime() + "     Courtesy of Peter J. " > $WinUpdateSettings;
$SCRIPT:AutoUpdateNotificationLevels = @{ 0 = "Not configured"; 1 = "Disabled"; 2 = "Notify before download"; 3 = "Notify before installation"; 4 = "Scheduled installation" };
$SCRIPT:AutoUpdateDays = @{ 0 = "Every Day"; 1 = "Every Sunday"; 2 = "Every Monday"; 3 = "Every Tuesday"; 4 = "Every Wednesday"; 5 = "Every Thursday"; 6 = "Every Friday"; 7 = "Every Saturday" };
$AUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
$AUObj = New-Object -TypeName System.Object
Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "NotificationLevel" -Value $AutoUpdateNotificationLevels[$AUSettings.NotificationLevel]
Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "UpdateDays" -Value $AutoUpdateDays[$AUSettings.ScheduledInstallationDay]
Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "UpdateHour" -Value $AUSettings.ScheduledInstallationTime
Add-Member -inputObject $AuObj -MemberType NoteProperty -Name "Recommended updates" -Value $(IF ($AUSettings.IncludeRecommendedUpdates) { "Included" }
	else { "Excluded" })
$AUSettings *>> $WinUpdateSettings;
$AuObj | Format-Table * *>> $WinUpdateSettings;

"" + (Get-Date).tostring() + " - Running:  Get-WindowsUpdateLog -LogPath " + ($OS_MiscFolder + "WindowsUpdate.log")
Write-Verbose -verbose "You may get a 'Security Alert' that says 'You are about to view pages over a secure connection', recommend clicking 'In the future, do not show this warning'"
$job = Start-Job -ScriptBlock { Get-WindowsUpdateLog -LogPath ($using:OS_MiscFolder + "WindowsUpdate.log") }; $Job | Wait-Job | Remove-Job #### Security Alert may be generated

if (Test-Path "C:\ProgramData\GuestConfig")
{
	if ($outputFolder -ne "" -and (Test-Path ($outputFolder + "ProgramData"))) { Remove-Item ($outputFolder + "ProgramData") -recurse -Force }
	CreateFolder ($outputFolder + "ProgramData\GuestConfig\")
	Get-ChildItem C:\ProgramData\GuestConfig -recurse > ($outputFolder + "ProgramData\GuestConfig\GuestConfig-Directory-listing.txt")
}

##  get C:\ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension
if (Test-Path "C:\ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension")
{
	"" + (Get-Date).tostring() + " - Copying C:\ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
	$ExtensionFolder = $outputFolder + "ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
	Copy-Item C:\ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension $ExtensionFolder -Recurse
}

##  get most recent logs from C:\ProgramData\GuestConfig\ext_mgr_logs
if (Test-Path "C:\ProgramData\GuestConfig\ext_mgr_logs")
{
	"" + (Get-Date).tostring() + " - Copying most recent files from C:\ProgramData\GuestConfig\ext_mgr_logs"
	$ExtMgrLogsFolder = $outputFolder + "ProgramData\GuestConfig\ext_mgr_logs"
	if (!(Test-Path $ExtMgrLogsFolder)) { New-Item -ItemType Directory -Path $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log"; if (Test-Path $ffile) { Copy-Item $ffile "$ExtMgrLogsFolder" }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.1.log"; if (Test-Path $ffile) { Copy-Item $ffile "$ExtMgrLogsFolder" }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.2.log"; if (Test-Path $ffile) { Copy-Item $ffile "$ExtMgrLogsFolder" }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.3.log"; if (Test-Path $ffile) { Copy-Item $ffile "$ExtMgrLogsFolder" }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_agent.json"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext_telemetry.txt"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext_telemetry.1.txt"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext_telemetry.2.txt"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext_telemetry.3.txt"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
	$ffile = "C:\ProgramData\GuestConfig\ext_mgr_logs\restart_ExtensionService.log"; if (Test-Path $ffile) { Copy-Item $ffile $ExtMgrLogsFolder }
}

##  get most recent logs from C:\ProgramData\GuestConfig\extension_reports
if (Test-Path "C:\ProgramData\GuestConfig\extension_reports")
{
	"" + (Get-Date).tostring() + " - Copying C:\ProgramData\GuestConfig\extension_reports"
	$ExtensionReports = $outputFolder + "ProgramData\GuestConfig\extension_reports"
	Copy-Item C:\ProgramData\GuestConfig\extension_reports $ExtensionReports -Recurse
	$WindowsOsUpdateExtension_report_File = $ExtensionReports + "\WindowsOsUpdateExtension_report.txt"
	$WindowsOsUpdateExtension_report_Friendly = $ExtensionReports + "\WindowsOsUpdateExtension_report_Friendly.txt"
	if (Test-Path $WindowsOsUpdateExtension_report_File)
	{
		
		$WindowsOsUpdateExtension_report = Get-Content $WindowsOsUpdateExtension_report_File | convertfrom-json
		$WindowsOsUpdateExtension_report | Format-List extensionHash, jobId, machineId, Name, Sent, sentSuccessfully, seqNumber > $WindowsOsUpdateExtension_report_Friendly
		"----------------" >> $WindowsOsUpdateExtension_report_Friendly
		"Status property:" >> $WindowsOsUpdateExtension_report_Friendly
		$WindowsOsUpdateExtension_report.status >> $WindowsOsUpdateExtension_report_Friendly
		$loc1 = $WindowsOsUpdateExtension_report.status.statusMessage.IndexOf('{')
		if ($loc1 -gt 1)
		{
			"-----------------------"  >> $WindowsOsUpdateExtension_report_Friendly
			"StatusMessage property:"  >> $WindowsOsUpdateExtension_report_Friendly
			$WindowsOsUpdateExtension_report.status.statusMessage.Substring(0, $loc1) >> $WindowsOsUpdateExtension_report_Friendly
			$WindowsOsUpdateExtension_report.status.statusMessage.Substring($loc1) | ConvertFrom-Json >> $WindowsOsUpdateExtension_report_Friendly
		}
	}
}

##  get C:\ProgramData\GuestConfig\Configuration
if (Test-Path "C:\ProgramData\GuestConfig\Configuration")
{
	"" + (Get-Date).tostring() + " - Copying C:\ProgramData\GuestConfig\Configuration"
	$GCconfiguration = $outputFolder + "ProgramData\GuestConfig\Configuration"
	Copy-Item C:\ProgramData\GuestConfig\Configuration $GCconfiguration -Recurse
}

if (Test-Path "C:\WindowsAzure\Logs")
{
	CreateFolder ($outputFolder + "WindowsAzure\Logs\")
	Get-ChildItem C:\WindowsAzure\Logs -recurse > ($outputFolder + "WindowsAzure\Logs\Logs-Directory-listing.txt")
}

##  get most recent C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension
$sourceFolder = "C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension"
if (Test-Path $sourceFolder)
{
	"" + (Get-Date).tostring() + " - Copying $sourceFolder"
	$AzureCplatCoreFolder = $outputFolder + $sourceFolder.Substring(3)
	$files = Get-ChildItem $sourceFolder | Sort-Object { [system.version]$_.Name } -Descending
	$folderPath = $files[0].FullName; if (Test-Path $folderPath) { Copy-Item $folderPath ($AzureCplatCoreFolder + $folderPath.Substring($folderPath.LastIndexOf("\"))) -Recurse }
	$folderPath = $files[1].FullName; if (Test-Path $folderPath) { Copy-Item $folderPath ($AzureCplatCoreFolder + $folderPath.Substring($folderPath.LastIndexOf("\"))) -Recurse }
	$folderPath = $files[2].FullName; if (Test-Path $folderPath) { Copy-Item $folderPath ($AzureCplatCoreFolder + $folderPath.Substring($folderPath.LastIndexOf("\"))) -Recurse }
}

if (Test-Path "C:\Packages")
{
	if ($outputFolder -ne "" -and (Test-Path ($outputFolder + "Packages"))) { Remove-Item ($outputFolder + "Packages") -recurse -Force }
	CreateFolder ($outputFolder + "Packages\")
	Get-ChildItem C:\Packages -recurse > ($outputFolder + "Packages\Packages-Directory-listing.txt")
}

##  get C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension
if (Test-Path C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension)
{
	"" + (Get-Date).tostring() + " - Copying C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension"
	$CplatCoreFolder = $outputFolder + "Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension"
	#if ($outputFolder -ne "" -and (Test-Path ($outputFolder+"Packages"))) {rd ($outputFolder+"Packages")  -recurse -Force}
	Copy-Item C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension $CplatCoreFolder -Recurse
	$Statusfiles = Get-ChildItem ($outputFolder + "Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\*.status") -Recurse
	$objStatusList = @()
	$StatusSummary = $outputFolder + "Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\Status_Summary.txt"
	$StatusSummaryDetailed = $outputFolder + "Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\Status_Summary_Detailed.txt"
	Foreach ($fileStatus in $Statusfiles)
	{
		#"Processing: " + $fileStatus.FullName
		"================================================================================================================" >> $StatusSummaryDetailed
		"================================================================================================================" >> $StatusSummaryDetailed
		"===  " + $fileStatus.FullName >> $StatusSummaryDetailed
		$JsonStatus = Get-Content $fileStatus.FullName | convertfrom-json
		$JsonStatus | Format-Table >> $StatusSummaryDetailed
		$JsonStatus.status.substatus | Format-Table Name, status, Code >> $StatusSummaryDetailed
		ForEach ($substatus in $JsonStatus.status.substatus)
		{
			$substatus | Format-Table Name, Status, Code >> $StatusSummaryDetailed
			$subStatusMessage = $substatus.formattedMessage.message | convertfrom-json
			$subStatusMessage >> $StatusSummaryDetailed
			$subStatusMessage.patches | Format-Table >> $StatusSummaryDetailed
		}
		$Statusobjxx = New-Object -TypeName PSObject
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Name -Value $JsonStatus.status.name
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Status -Value $JsonStatus.status.status
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Operation -Value $JsonStatus.status.operation
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Code -Value $JsonStatus.status.code
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Message -Value $JsonStatus.status.formattedMessage.message
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name timestampUTC -Value $JsonStatus.timestampUTC
		$objStatusList += $Statusobjxx
	}
	$objStatusList | Sort-Object TimestampUTC | Format-Table TimestampUTC, Operation, Status, Message > $StatusSummary
}

##  get VMGuest data in case of UMC or VMGuestPatching
##  C:\Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension
if (Test-Path C:\Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension)
{
	"" + (Get-Date).tostring() + " - Copying C:\Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
	$WinOSStatusFolder = $outputFolder + "Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
	#if ($outputFolder -ne "" -and (Test-Path ($outputFolder+"Packages"))) {rd ($outputFolder+"Packages")  -recurse -Force}   ###############
	Copy-Item C:\Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension $WinOSStatusFolder -Recurse
	$Statusfiles = Get-ChildItem ($outputFolder + "Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension\*.status") -Recurse
	$objStatusList = @()
	$StatusSummary = $outputFolder + "Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension\Status_Summary.txt"
	Foreach ($fileStatus in $Statusfiles)
	{
		#"Processing: " + $fileStatus.FullName
		$JsonStatus = Get-Content $fileStatus.FullName | convertfrom-json
		$Statusobjxx = New-Object -TypeName PSObject
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Name -Value $JsonStatus.status.name
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Status -Value $JsonStatus.status.status
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Operation -Value $JsonStatus.status.operation
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Code -Value $JsonStatus.status.code
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name Message -Value $JsonStatus.status.formattedMessage.message
		$Statusobjxx | Add-Member -MemberType NoteProperty -Name ConfigurationAppliedTime -Value $JsonStatus.status.configurationAppliedTime
		$objStatusList += $Statusobjxx
	}
	(Get-Date).tostring() + " - Below is a summary of all of the '*.status' files found in the subfolders $crlf" > $StatusSummary
	$objStatusList | Sort-Object ConfigurationAppliedTime -Descending | Format-Table Operation, code, ConfigurationAppliedTime, Message >> $StatusSummary
}

## Getting Arc data, azcmagent Logs, azcmagent Show and azcmagent Check
$azcmagent = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
if (Test-Path $azcmagent)
{
	$arcFolder = $outputFolder + "arc\"
	if (!(Test-Path $arcFolder)) { New-Item -ItemType Directory -Path $arcFolder }
	&$azcmagent show > ($arcFolder + "Azcmagent_show.txt")
	&$azcmagent check > ($arcFolder + "Azcmagent_check.txt")
	&$azcmagent check -p > ($arcFolder + "Azcmagent_check_Private_ignore_if_not_using_privateLink.txt")
	
	$azcmagentlogs = $arcFolder + "azcmagent-logs-" + (Get-Date -Format yyMMddTHHmm) + "-" + $env:computername + ".zip"
	if (Test-Path ($arcFolder + "azcmagent-logs*.zip")) { Remove-Item ($arcFolder + "azcmagent-logs*.zip") }
	azcmagent logs -o $azcmagentlogs
}
else { CopyFile C:\WindowsAzure\Logs\WaAppAgent.log $outputFolder } ## if not Arc there should be a WaAppAgent.log


## Getting currently install updates and what client initiated the updates
If ($GetUpdateInfo)
{
	"" + (Get-Date).tostring() + " - Collecting update information from ComObject Microsoft.Update"
	$Scriptblock = {
		$job = Start-Job -ScriptBlock $Scriptblock; $Job | Wait-Job | Remove-Job
		$UpdateInfo = $using:outputFolder + "Update_Info.txt"
		"== Data collected at UTC: " + (Get-Date).ToUniversalTime().ToString() + "  /  Local Time: " + (Get-Date).ToString() + "  /  From Computer: $env:COMPUTERNAME" > $UpdateInfo
		$rebootData = Get-WinEvent -FilterHashtable @{ logname = 'System'; id = 1074 } | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Message | Select-Object -Last 10 | Format-Table -AutoSize -Wrap | Out-String -Width 160
		$operation = @('Unk', 'Installation', 'Uninstallation', 'Other')
		$resultCode = @('Unk', 'In Progress', 'Succeeded', 'Succeeded With Errors', 'Failed', 'Aborted')
		$updateSession = New-Object -ComObject Microsoft.Update.Session
		$updateSearcher = $updateSession.CreateUpdateSearcher()
		$historyCount = $updateSearcher.GetTotalHistoryCount()
		$filterOutString = "*defender antivirus*"
		$allUpdatesExceptDefender = $updateSearcher.QueryHistory(0, $historyCount) |
		Select-Object Date,
					  @{ N = 'Operation'; E = { $operation[$_.operation] } },
					  @{ N = 'Status'; E = { $resultCode[$_.resultcode] } },
					  Title, ClientApplicationID, ServerSelection, type |
		Where-Object { ![String]::IsNullOrWhiteSpace($_.title) -and ($_.title -notlike $filterOutString -and $_.title -notlike "*- Printer -*") } | Sort-Object Date -Descending -Unique # exclude Microsoft Defender, unable to specify type in history to exclude drivers so filtered out - printer -
		$last2DefenderUpdates = $updateSearcher.QueryHistory(0, $historyCount) |
		Select-Object Date,
					  @{ N = 'Operation'; E = { $operation[$_.operation] } },
					  @{ N = 'Status'; E = { $resultCode[$_.resultcode] } },
					  Title, ClientApplicationID, ServerSelection |
		Where-Object { ![String]::IsNullOrWhiteSpace($_.title) -and $_.title -like $filterOutString } | Sort-Object Date -Unique -Descending | Select-Object -Last 2 | Format-Table -AutoSize | Out-String -Width 300
		$SearchResult = $UpdateSearcher.Search("Type='Software'") #IsInstalled=0 and 
		$installedAndNotInstalled = $SearchResult.Updates | Sort-Object LastDeploymentChangeTime, IsInstalled, Title -Descending | Format-Table  @{ Label = 'ReleaseDate'; Expression = { ($_.LastDeploymentChangeTime).ToShortDateString() } }, Title, IsInstalled, RebootRequired, AutoSelection, AutoDownload, IsPresent -AutoSize | Out-String -Width 300
		"== Data collected at UTC: " + (Get-Date).ToUniversalTime().ToString() + "  /  Local Time: " + (Get-Date).ToString() + "  /  From Computer: $env:COMPUTERNAME" > $UpdateInfo
		"" >> $UpdateInfo
		"== Software Updates" >> $UpdateInfo
		$installedAndNotInstalled >> $UpdateInfo
		"" >> $UpdateInfo
		"== Past 4 months of updates with ClientApplicationID that initiated update, except Microsoft Defender updates and '- Printer -' updates" >> $UpdateInfo
		$StartDate = (Get-Date).AddMonths(-4)
		$allUpdatesExceptDefender | Where-Object{ $_.Date -gt $StartDate } | Format-Table -AutoSize | Out-String -Width 300   >> $UpdateInfo
		"" >> $UpdateInfo
		"== Recent system Event ID 1074 records.  For more detail filter system event log with: 1074, 26, 6006, 6009, 19, 20, 2004, 1022, 43, 109" >> $UpdateInfo
		$rebootData >> $UpdateInfo
		"" >> $UpdateInfo
		"== Two most recent Microsoft Defender updates:" >> $UpdateInfo
		$last2DefenderUpdates >> $UpdateInfo
		$ClientApplicationID = @'

NOTE: The Windows Update Service is used to install updates, however it is the ClientApplicationID that initiates the request to the Windows Update Service. 
      The following Table can be used to help establish the application that initiated the request to the Windows Update Service.  If you have information that 
      can improve the table below please email AustinM


ClientApplicationID                             Process initiating the request to the Windows Update service
===================                             =================================================================================
UpdateManagment_Patch-MicrosoftOMSComputer      Azure Update management v1 initiating Windows Update Service to install update(s)
Windows Defender                                update initiated by Windows Defender on the local system
MoUpdateOrchestrator	                        Windows
Update	                                        ??? (I believe this is local Windows)
CcmExec	                                        SMS (Systems Management Server) Agent Host service
UpdateOrchestrator                              Update Orchestrator Service - Manages Windows Updates. 
UpdateAgentLCU	                                used to install servicing stack updates.   
Azure VM Guest Patching	                        Azure "Update Manager" 
WindowsOsUpdateExtension                        Azure ARC Update Manager 
OperationalInsight                              ??? 
SqlIaaSExtension.Service.exe	                Azure SQL Virtual Machine - Updates  
wusa	                                        Windows Update Standalone Installer
UpdateManagementActionExec.exe	                VMguest patching - C:\packages\plugins\Microsoft.SoftwareUpdateManagement.Windows.OSUpdateExtension\UpdateManagementActionExec.exe

If you do not want Azure VMGuest Patching to randomly install updates after 10 PM local Regional time change the system to "Customer managed Schedules" in Update Manager

'@
		$ClientApplicationID >> $UpdateInfo
	}
	$job = Start-Job -ScriptBlock $Scriptblock; $Job | Wait-Job | Remove-Job
}




Start-Process ($outputFolder + ".")
Write-Verbose -verbose "Please zip up $outputFolder and all of the subfolders in it and upload the zip file to Microsoft transfer site"
"== " + (Get-Date).tostring() + " Done"
