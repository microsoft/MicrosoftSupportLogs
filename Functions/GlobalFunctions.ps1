$script:CRLF = "`r`n"

function Time-Stamp
{
	param (
		[switch]$UniversalTime,
		[switch]$IncludeTimeZone
	)
	
	# Get current date and time based on the UniversalTime switch
	$TodaysDate = if ($UniversalTime) { [DateTime]::UtcNow }
	else { [DateTime]::Now }
	
	# Extract components manually for compatibility
	$day = $TodaysDate.Day.ToString("D2")
	$month = $TodaysDate.Month.ToString("D2")
	$year = $TodaysDate.Year
	$hour = $($TodaysDate.Hour % 12).ToString("D2")
	if ($hour -eq '00') { $hour = '12' } # Adjust for 12-hour format
	$minute = $TodaysDate.Minute.ToString("D2") # Pad minute with leading zero if needed
	$second = $TodaysDate.Second.ToString("D2") # Pad second with leading zero if needed
	$amPm = if ($TodaysDate.Hour -ge 12) { "PM" }
	else { "AM" }
	
	# Format the date and time string
	$timeStamp = "$month/$day/$year $hour`:$minute`:$second $amPm"
	
	# Add time zone if IncludeTimeZone is specified
	if ($IncludeTimeZone)
	{
		$timeZone = if ($UniversalTime) { "UTC" }
		else { [System.TimeZoneInfo]::Local.StandardName }
		$timeStamp = "$timeStamp ($timeZone)"
	}
	
	return $timeStamp
}

function Write-Console
{
	[CmdletBinding()]
	param (
		# =====================================================
		# Parameters for the Write-Console Function
		# =====================================================
		
		# Optional parameter for a simple text message
		[Parameter(Mandatory = $false)]
		[string]$Text,
		# Optional parameter for an array of message segments (for colorized output)
		[Parameter(Mandatory = $false)]
		[Array]$MessageSegments,
		# Optional foreground color for the timestamp text
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta',
					 'DarkYellow', 'Gray', 'DarkGray', 'Cyan', 'Green', 'Red',
					 'Magenta', 'Yellow', 'White', 'Default', 'Rainbow')]
		[string]$TimestampColor,
		# Optional background color for the timestamp
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta',
					 'DarkYellow', 'Gray', 'DarkGray', 'Cyan', 'Green', 'Red',
					 'Magenta', 'Yellow', 'White')]
		[string]$TimestampBackgroundColor,
		# Optional foreground color for the text (used with -Text parameter)
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta',
					 'DarkYellow', 'Gray', 'DarkGray', 'Cyan', 'Green', 'Red',
					 'Magenta', 'Yellow', 'White', 'Default', 'Rainbow')]
		[string]$ForegroundColor,
		# Optional background color for the text (used with -Text parameter)
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta',
					 'DarkYellow', 'Gray', 'DarkGray', 'Cyan', 'Green', 'Red',
					 'Magenta', 'Yellow', 'White')]
		[string]$BackgroundColor,
		# Optional foreground color for the separator text
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta',
					 'DarkYellow', 'Gray', 'DarkGray', 'Cyan', 'Green', 'Red',
					 'Magenta', 'Yellow', 'White', 'Default', 'Rainbow')]
		[string]$SeparatorColor,
		# Switch to suppress the timestamp output
		[Parameter(Mandatory = $false)]
		[switch]$NoTimestamp,
		# Switch to suppress the newline after the message
		[Parameter(Mandatory = $false)]
		[switch]$NoNewLine,
		# Switch to enable Read-Host functionality
		[Parameter(Mandatory = $false)]
		[switch]$ReadHost
	)
	
	# =====================================================
	# Initialize Variables
	# =====================================================
	
	# Initialize the separator as an empty string
	$separator = ""
	
	# Set the log file path (adjust this path as needed)
	$logFilePath = "$outputFolder\script-log.log"
	
	# Ensure the log directory exists
	$logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
	if (!(Test-Path -Path $logDirectory -ErrorAction SilentlyContinue))
	{
		# Create the directory if it doesn't exist
		New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
	}
	
	# Initialize the script-scoped log buffer if not already initialized
	if (-not ($script:logBuffer))
	{
		$script:logBuffer = ""
	}
	
	# =====================================================
	# Helper Functions
	# =====================================================
	
	function Get-UniqueColorIndex
	{
		param (
			[int]$Min = 0,
			[int]$Max = 7
		)
		if (-not ($script:previousColorIndex -ne $null))
		{
			$script:previousColorIndex = -1
		}
		do
		{
			$newColorIndex = Get-Random -Minimum $Min -Maximum $Max
		}
		while ($newColorIndex -eq $script:previousColorIndex)
		$script:previousColorIndex = $newColorIndex
		return $newColorIndex
	}
	
	function Output-ColorizedText
	{
		param (
			[string]$Text,
			[string]$ForegroundColor,
			[string]$BackgroundColor,
			[switch]$NoNewLine = $true
		)
		
		if ($ForegroundColor -eq 'Rainbow')
		{
			$rainbowColors = @('Red', 'DarkYellow', 'Yellow', 'Green', 'Cyan', 'DarkMagenta', 'Magenta')
			foreach ($char in $Text.ToCharArray())
			{
				$colorIndex = Get-UniqueColorIndex -Min 0 -Max 7
				$currentColor = $rainbowColors[$colorIndex % $rainbowColors.Count]
				$charParams = @{
					'Object'		  = $char
					'NoNewline'	      = $NoNewLine
					'ForegroundColor' = $currentColor
				}
				if ($BackgroundColor -and $BackgroundColor -ne 'Default')
				{
					$charParams['BackgroundColor'] = $BackgroundColor
				}
				Write-Host @charParams
			}
		}
		else
		{
			$writeHostParams = @{
				'Object'    = $Text
				'NoNewline' = $NoNewLine
			}
			if ($ForegroundColor -and $ForegroundColor -ne 'Default')
			{
				$writeHostParams['ForegroundColor'] = $ForegroundColor
			}
			if ($BackgroundColor -and $BackgroundColor -ne 'Default')
			{
				$writeHostParams['BackgroundColor'] = $BackgroundColor
			}
			Write-Host @writeHostParams
		}
	}
	
	function Append-ToLogBuffer
	{
		param (
			[string]$Content
		)
		$script:logBuffer += $Content
	}
	
	function Write-AndLog
	{
		param (
			[string]$Text,
			[string]$ForegroundColor,
			[string]$BackgroundColor,
			[string]$Indent = ""
		)
		# Split the text by newline characters
		$lines = $Text -split "(\r\n|\n|\r)"
		$firstLine = $true
		foreach ($line in $lines)
		{
			if (-not $firstLine)
			{
				# Add indentation for subsequent lines
				Append-ToLogBuffer -Content "$Indent$line"
				Output-ColorizedText -Text "$Indent$line" -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
			}
			else
			{
				Append-ToLogBuffer -Content $line
				Output-ColorizedText -Text $line -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
				$firstLine = $false
			}
		}
	}
	
	# =====================================================
	# Timestamp Handling Section
	# =====================================================
	
	$indentation = ""
	if (-not $NoTimestamp)
	{
		$timestamp = (Time-Stamp).Trim()
		Write-AndLog -Text $timestamp -ForegroundColor $TimestampColor -BackgroundColor $TimestampBackgroundColor
		
		# Separator Handling
		$separator = " - "
		Write-AndLog -Text $separator -ForegroundColor $SeparatorColor
		
		# Calculate indentation length
		$indentation = " " * ($timestamp.Length + $separator.Length)
	}
	
	# =====================================================
	# Message Output Handling Section
	# =====================================================
	
	if ($ReadHost)
	{
		# Build the prompt text
		$promptText = ""
		
		if ($PSBoundParameters.ContainsKey('Text') -and $null -ne $Text)
		{
			$promptText = $Text + ": "
			Write-AndLog -Text $promptText -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
		}
		elseif ($PSBoundParameters.ContainsKey('MessageSegments') -and $null -ne $MessageSegments)
		{
			foreach ($segment in $MessageSegments)
			{
				Write-AndLog -Text $segment.Text -ForegroundColor $segment.ForegroundColor -BackgroundColor $segment.BackgroundColor
			}
			Write-AndLog -Text ": "
		}
		else
		{
			$warningMessage = "Error: Please provide either -Text or -MessageSegments for the prompt."
			Append-ToLogBuffer -Content $warningMessage
			Write-Warning $warningMessage
			return
		}
		
		# Read the user's input
		$userInput = Read-Host
		
		# Append the user's input to the log buffer
		Append-ToLogBuffer -Content $userInput
		
		if (-not $NoNewLine)
		{
			Write-Host ""
		}
		
		# Write the accumulated log buffer to the log file
		try
		{
			Add-Content -Path $logFilePath -Value $script:logBuffer
		}
		catch
		{
			Write-Warning "Failed to write to log file: $_"
		}
		
		# Clear the log buffer
		$script:logBuffer = ""
		
		# Return the user's input
		return $userInput
	}
	elseif ($PSBoundParameters.ContainsKey('Text') -and $null -ne $Text)
	{
		Write-AndLog -Text $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -Indent $indentation
	}
	elseif ($PSBoundParameters.ContainsKey('MessageSegments') -and $null -ne $MessageSegments)
	{
		# Combine all segments into one string to handle newlines properly
		$combinedText = ""
		$combinedSegments = @()
		foreach ($segment in $MessageSegments)
		{
			$combinedText += $segment.Text
			$combinedSegments += [PSCustomObject]@{
				Text		    = $segment.Text
				ForegroundColor = $segment.ForegroundColor
				BackgroundColor = $segment.BackgroundColor
			}
		}
		
		# Split the combined text by newline characters
		$lines = $combinedText -split "(\r\n|\n|\r)"
		$firstLine = $true
		$segmentIndex = 0
		foreach ($line in $lines)
		{
			if (-not $firstLine)
			{
				# Add indentation for subsequent lines
				Write-Host -NoNewline $indentation
				Append-ToLogBuffer -Content "$indentation"
			}
			$lineSegments = $line
			if ($line -ne "")
			{
				foreach ($segment in $combinedSegments)
				{
					$text = $segment.Text
					if ($text.Length -le 0) { continue }
					
					$segmentText = $text.Substring(0, [Math]::Min($line.Length - $segmentIndex, $text.Length))
					$segmentIndex += $segmentText.Length
					
					Write-AndLog -Text $segmentText -ForegroundColor $segment.ForegroundColor -BackgroundColor $segment.BackgroundColor -Indent ""
					$segment.Text = $text.Substring($segmentText.Length)
				}
			}
			else
			{
				Write-Host ""
				Append-ToLogBuffer -Content "`n"
			}
			$firstLine = $false
			$segmentIndex = 0
		}
	}
	else
	{
		$warningMessage = "Error: Please provide either -Text or -MessageSegments"
		Append-ToLogBuffer -Content $warningMessage
		Write-Warning $warningMessage
	}
	
	# =====================================================
	# Newline Handling and Logging Section
	# =====================================================
	
	if (-not $NoNewLine)
	{
		Write-Host ""
		try
		{
			Add-Content -Path $logFilePath -Value $script:logBuffer
		}
		catch
		{
			Write-Warning "Failed to write to log file: $_"
		}
		$script:logBuffer = ""
	}
}

function New-MessageSegment
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$Text,
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed',
					 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Cyan',
					 'Green', 'Red', 'Magenta', 'Yellow', 'White', 'Rainbow')]
		[string]$ForegroundColor,
		[Parameter()]
		[ValidateSet(
					 'Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed',
					 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Cyan',
					 'Green', 'Red', 'Magenta', 'Yellow', 'White')]
		[string]$BackgroundColor = $null
	)
	
	return @{
		Text		    = $Text
		ForegroundColor = $ForegroundColor
		BackgroundColor = $BackgroundColor
	}
}

<#
------------------------------------------------------
                        Example
------------------------------------------------------
$messageSegments = @(
    New-MessageSegment -Text "Starting data collection" -ForegroundColor 'DarkCyan'
    New-MessageSegment -Text " - " -ForegroundColor 'Red' -BackgroundColor 'Black'
    New-MessageSegment -Text "Please wait..." -ForegroundColor 'Yellow'
)

Write-Console -MessageSegments $messageSegments -TimestampColor White -TimestampBackgroundColor DarkBlue -SeparatorColor Red

------------------------------------------------------
                        Example
------------------------------------------------------

Write-Console -Text "This is pretty cool!" -ForegroundColor Rainbow -TimestampColor Rainbow -SeparatorColor Rainbow -NoNewLine


------------------------------------------------------
                        Example
------------------------------------------------------

$x = 0; do{Write-Console -Text "This is pretty cool!" -ForegroundColor Rainbow -TimestampColor Rainbow -SeparatorColor Rainbow; Start-Sleep -Milliseconds 500; $x++;}until($x -eq 15)
#>

function Out-FileWithErrorHandling
{
	[CmdletBinding(DefaultParameterSetName = 'ByPath', SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $false,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[System.Object]$InputObject,
		[Parameter(Position = 0,
				   Mandatory = $true,
				   ParameterSetName = 'ByPath')]
		[Alias('File')]
		[string]$FilePath,
		[switch]$Append,
		[switch]$NoClobber,
		[ValidateSet('ascii', 'bigendianunicode', 'default', 'oem', 'string',
					 'unicode', 'unknown', 'utf32', 'utf7', 'utf8', 'utf8bom', 'utf8nobom')]
		[string]$Encoding = 'default',
		[int]$Width = 4096,
		[switch]$Force
	)
	
	begin
	{
		try
		{
			# Resolve the full path to the specified file.
			$FullFilePath = [System.IO.Path]::GetFullPath($FilePath)
			# Initialize an array to collect pipeline input.
			$collectedInput = @()
		}
		catch
		{
			# If the file path resolution fails, display an error and stop.
			Write-Error "Failed to initialize file operation for '$FilePath'. Error: $($_.Exception.Message)"
			return
		}
	}
	
	process
	{
		try
		{
			# Append the current pipeline input object to the collection if it is not null.
			if ($null -ne $InputObject)
			{
				$collectedInput += $InputObject
			}
		}
		catch
		{
			# If any error occurs while processing input, display an error.
			Write-Error "Failed to process input for '$FilePath'. Error: $($_.Exception.Message)"
		}
	}
	
	end
	{
		try
		{
			# If NoClobber is specified and the file already exists, do not overwrite it.
			if ($NoClobber -and (Test-Path $FullFilePath))
			{
				Write-Error "File '$FullFilePath' already exists and NoClobber is specified. No overwrite performed."
				return
			}
			
			# Check if the action should be performed as per the user's confirmation settings.
			if ($PSCmdlet.ShouldProcess($FullFilePath, "Write content to file"))
			{
				# If Width is provided, configure Out-String to use that width.
				$osParams = @{ }
				if ($Width) { $osParams['Width'] = $Width }
				
				# Convert the collected input into a single string.
				$content = $collectedInput | Out-String @osParams
				
				# If required, uncomment the next line to remove non-ASCII characters:
				# $content = $content -replace '[^\x20-\x7E\r\n]', ''
				
				# If Append is specified, append to the existing file; otherwise, overwrite/create new.
				if ($Append)
				{
					Add-Content -Path $FullFilePath -Force:$Force -Encoding $Encoding -Value $content
				}
				else
				{
					Set-Content -Path $FullFilePath -Force:$Force -Encoding $Encoding -Value $content
				}
			}
		}
		catch
		{
			# If any error occurs during the file write operation, display an error.
			Write-Error "Failed to write to file '$FullFilePath'. Error: $($_.Exception.Message)"
		}
	}
}

#region SSL Configuration Testing Functions

#region Helper Functions

function Is-IPv6Enabled
{
	# Use .NET to check all network interfaces
	$interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
	foreach ($interface in $interfaces)
	{
		# Check if interface has IPv6 unicast addresses, indicating IPv6 is enabled
		$ipv6Addresses = $interface.GetIPProperties().UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
		if ($ipv6Addresses.Count -gt 0)
		{
			return $true
		}
	}
	return $false
}

function Format-CipherSuite
{
	param (
		[string]$Name,
		[string]$Protocol,
		[int]$Strength
	)
	$status = "Supported"
	$output = "{0,-40} {1,-10} {2,-11} {3,14}" -f $Name, $status, $Protocol, $Strength
	Write-Output $output
}

# Helper Function: Test-TlsProtocols
function Test-TlsProtocols
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$FQDN,
		[Parameter(Mandatory = $false)]
		[int]$Port = 443
	)
	
	$protocols = @()
	
	if ([Enum]::IsDefined([System.Security.Authentication.SslProtocols], 'Tls13'))
	{
		$protocols += [System.Security.Authentication.SslProtocols]::Tls13
	}
	
	$protocols += [System.Security.Authentication.SslProtocols]::Tls12
	$protocols += [System.Security.Authentication.SslProtocols]::Tls11
	$protocols += [System.Security.Authentication.SslProtocols]::Tls
	
	$results = @()
	
	foreach ($protocol in $protocols)
	{
		$tcpClient = $null
		$sslStream = $null
		try
		{
			$tcpClient = New-Object System.Net.Sockets.TcpClient($FQDN, $Port)
			$sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, ({ $true }))
			
			# Specify only the protocol being tested
			$sslStream.AuthenticateAsClient($FQDN, $null, $protocol, $false)
			
			# Check if the negotiated protocol matches the one being tested
			if ($sslStream.SslProtocol -eq $protocol)
			{
				$status = 'Supported'
			}
			else
			{
				$status = 'Not Supported'
			}
		}
		catch
		{
			$status = 'Not Supported'
		}
		finally
		{
			if ($sslStream) { $sslStream.Dispose() }
			if ($tcpClient) { $tcpClient.Close() }
		}
		
		# Correctly format the protocol names
		$protocolEnumName = $protocol.ToString()
		$protocolDisplayName = switch ($protocolEnumName)
		{
			"Tls13" { "TLS 1.3" }
			"Tls12" { "TLS 1.2" }
			"Tls11" { "TLS 1.1" }
			"Tls"   { "TLS 1.0" }
			default { $protocolEnumName }
		}
		$protocolName = "$protocolDisplayName ($protocolEnumName)"
		
		$results += [PSCustomObject]@{
			Protocol = $protocolName
			Status   = $status
		}
	}
	return $results
}

# Helper Function: Format-SslProtocol
function Format-SslProtocol
{
	param (
		[System.Security.Authentication.SslProtocols]$SslProtocol
	)
	$protocolEnumName = $SslProtocol.ToString()
	$protocolDisplayName = switch ($protocolEnumName)
	{
		"Tls13" { "TLS 1.3" }
		"Tls12" { "TLS 1.2" }
		"Tls11" { "TLS 1.1" }
		"Tls"   { "TLS 1.0" }
		"None"  { "None" }
		default { $protocolEnumName }
	}
	return "$protocolDisplayName ($protocolEnumName)"
}

#endregion Helper Functions

#region Certificate Validation Function
# Helper Function: Get-CertificateValidationStatus
function Get-CertificateValidationStatus
{
	param (
		[string]$FQDN,
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)
	$certChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
	$certChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
	$certChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
	$certChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
	$certChain.ChainPolicy.UrlRetrievalTimeout = (New-TimeSpan -Seconds 30)
	$isValid = $certChain.Build($Certificate)
	$validationMessage = $null
	if (-not $isValid)
	{
		$validationMessage = ($certChain.ChainStatus | Select-Object -ExpandProperty StatusInformation) -join "; "
	}
	return [PSCustomObject]@{
		IsValid		      = $isValid
		ValidationMessage = $validationMessage
		Details		      = $certChain
	}
}
#endregion Certificate Validation Function

#region Main SSL Testing Function
# Main Function: Test-SSLConfiguration
function Test-SSLConfiguration
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$FQDNs,
		[Parameter(Mandatory = $false)]
		[ValidateRange(1, 65535)]
		[int]$Port = 443,
		[Parameter(Mandatory = $false)]
		[string]$SummaryOutputFile = "CheckSSL_Summary.txt"
	)
	
	# Initialize analysis data
	$analysis = @{
		Timestamp = Get-Date
		Endpoints = @()
		Summary   = @{
			TotalEndpoints	     = 0
			UnreachableEndpoints = 0
			ValidCertificates    = 0
			InvalidCertificates  = 0
			ExpiredCertificates  = 0
			TLS13Support		 = 0
			TLS12Support		 = 0
			TLS11Support		 = 0
			TLS10Support		 = 0
		}
	}
	
	foreach ($FQDN in $FQDNs)
	{
		Write-Output "$script:CRLF================================================================================"
		Write-Output "== Target: $FQDN"
		
		# Initialize endpoint data
		$endpoint = @{
			Target		      = $FQDN
			IPs			      = @()
			Status		      = ''
			CertIssuer	      = ''
			TLSProtocols	  = @()
			Error			  = ''
			ValidationMessage = ''
		}
		$analysis.Summary.TotalEndpoints++
		
		# Test DNS resolution
		try
		{
			# Check if IPv6 is enabled
			$ipv6Enabled = Is-IPv6Enabled
			
			# Retrieve and filter IP addresses based on IPv6 availability
			$addresses = [System.Net.Dns]::GetHostAddresses($FQDN) | ForEach-Object {
				if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
				{
					$_.IPAddressToString # IPv4
				}
				elseif ($ipv6Enabled -and $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
				{
					$_.IPAddressToString # IPv6 (only if enabled)
				}
			}
			
			# Display the filtered IP addresses
			Write-Output "== IP Addresses $(if($addresses.Count -gt 1){ "(count: $($addresses.Count))"}): $($addresses -join "; ")"
			# Collect IP addresses into $endpoint.IPs
			$endpoint.IPs = $addresses
		}
		catch
		{
			Write-Output "[ERROR] Could not resolve the hostname '$FQDN'. Please check the hostname and try again."
			# Record error in $endpoint
			$endpoint.Status = "ERROR"
			$endpoint.Error = "Could not resolve the hostname '$FQDN'"
			$analysis.Summary.UnreachableEndpoints++
			# Add endpoint to analysis data
			$analysis.Endpoints += $endpoint
			continue
		}
		Write-Output "----------------------------------------"
		
		try
		{
			# Establish SSL connection
			$tcpClient = New-Object System.Net.Sockets.TcpClient($FQDN, $Port)
			
			# Define the validation callback
			$validationCallback = {
				param (
					$sender,
					$certificate,
					$chain,
					$sslPolicyErrors
				)
				$global:sslPolicyErrors = $sslPolicyErrors
				$global:sslChainStatus = $chain.ChainStatus
				return $true # Allow handshake to continue
			}
			
			$sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $validationCallback)
			
			try
			{
				# Build the list of supported protocols
				$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
				if ([Enum]::IsDefined([System.Security.Authentication.SslProtocols], 'Tls13'))
				{
					$sslProtocols = $sslProtocols -bor [System.Security.Authentication.SslProtocols]::Tls13
				}
				
				# Authenticate with highest supported protocols
				$sslStream.AuthenticateAsClient($FQDN, $null, $sslProtocols, $false)
			}
			catch [System.Security.Authentication.AuthenticationException] {
				Write-Output "[WARNING] Authentication failed for $FQDN`: $($_.Exception.Message)"
			}
			
			# SSL Stream Information
			Write-Output "$script:CRLF`SSL Stream Information:"
			Write-Output "-----------------------"
			$sslInfo = [PSCustomObject]@{
				SslProtocol		     = Format-SslProtocol $sslStream.SslProtocol
				CipherAlgorithm	     = $sslStream.CipherAlgorithm
				CipherStrength	     = $sslStream.CipherStrength
				HashAlgorithm	     = $sslStream.HashAlgorithm
				HashStrength		 = $sslStream.HashStrength
				KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
				KeyExchangeStrength  = $sslStream.KeyExchangeStrength
				IsAuthenticated	     = $sslStream.IsAuthenticated
				IsEncrypted		     = $sslStream.IsEncrypted
				IsSigned			 = $sslStream.IsSigned
				CheckCertRevocation  = $true
			}
			Write-Output ($sslInfo | Format-List | Out-String).Trim()
			
			# Certificate Information
			Write-Output "$script:CRLF`Certificate Information:"
			Write-Output "----------------------------------------"
			$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
			
			# Validate Certificate
			$certValidation = Get-CertificateValidationStatus -FQDN $FQDN -Certificate $cert
			
			# Process validation results
			$daysUntilExpiration = [math]::Ceiling(($cert.NotAfter - (Get-Date)).TotalDays)
			$expirationInfo = if ($daysUntilExpiration -lt 0)
			{
				"Certificate expired $(-$daysUntilExpiration) days ago"
			}
			else
			{
				"Certificate valid for $daysUntilExpiration days"
			}
			
			$certInfo = [PSCustomObject]@{
				Subject	       = $cert.Subject
				Issuer		   = $cert.Issuer
				NotBefore	   = $cert.NotBefore.ToString('M/d/yyyy h:mm:ss tt')
				NotAfter	   = $cert.NotAfter.ToString('M/d/yyyy h:mm:ss tt')
				Thumbprint	   = $cert.Thumbprint
				SerialNumber   = $cert.SerialNumber
				ExpirationInfo = $expirationInfo
			}
			Write-Output ($certInfo | Format-List | Out-String).Trim()
			
			if ($cert.Extensions["2.5.29.17"])
			{
				Write-Output "$script:CRLF`Subject Alternative Names:"
				Write-Output "----------------------------------------"
				Write-Output $cert.Extensions["2.5.29.17"].Format($false)
			}
			
			# Display Validation Result
			Write-Output "$script:CRLF`Certificate Validation Result:"
			Write-Output "----------------------------------------"
			if ($certValidation.IsValid)
			{
				Write-Output "VALID"
				$endpoint.Status = "Valid Certificate"
				$analysis.Summary.ValidCertificates++
				$endpoint.CertIssuer = $cert.Issuer
			}
			else
			{
				Write-Output "INVALID"
				Write-Output "Error: $($certValidation.ValidationMessage)"
				$endpoint.Status = "Invalid Certificate"
				$endpoint.ValidationMessage = $certValidation.ValidationMessage
				$analysis.Summary.InvalidCertificates++
				# Check if the certificate is expired
				if ($cert.NotAfter -lt (Get-Date))
				{
					$analysis.Summary.ExpiredCertificates++
				}
			}
			
			# Test Supported TLS Protocols
			Write-Output "$script:CRLF`Supported TLS Protocols:"
			Write-Output "----------------------------------------"
			$tlsProtocols = Test-TlsProtocols -FQDN $FQDN -Port $Port
			
			# Collect TLS protocol support
			$protocolsAdded = @()
			foreach ($protocolResult in $tlsProtocols)
			{
				$protocolName = $protocolResult.Protocol
				$status = $protocolResult.Status
				
				if ($status -eq 'Supported')
				{
					$endpoint.TLSProtocols += $protocolName
					if ($protocolName -notin $protocolsAdded)
					{
						switch ($protocolName)
						{
							"TLS 1.3 (Tls13)" { $analysis.Summary.TLS13Support++ }
							"TLS 1.2 (Tls12)" { $analysis.Summary.TLS12Support++ }
							"TLS 1.1 (Tls11)" { $analysis.Summary.TLS11Support++ }
							"TLS 1.0 (Tls)"   { $analysis.Summary.TLS10Support++ }
						}
						$protocolsAdded += $protocolName
					}
				}
			}
			
			# Display the formatted protocols
			($tlsProtocols | Format-Table Protocol, Status | Out-String).Trim() | Write-Output
			
		}
		catch
		{
			Write-Output "[ERROR] Testing $FQDN failed: $($_.Exception.Message)"
			$endpoint.Status = "ERROR"
			$endpoint.Error = $_.Exception.Message
			$analysis.Summary.UnreachableEndpoints++
		}
		finally
		{
			if ($sslStream) { $sslStream.Dispose() }
			if ($tcpClient) { $tcpClient.Dispose() }
		}
		
		# Add endpoint to analysis data
		$analysis.Endpoints += $endpoint
	}
	
	# Generate report after processing all FQDNs
	$separator = "=" * 80
	
	$report = @"
SSL/TLS Analysis Report
Generated: $($analysis.Timestamp)

Summary:
--------
Total Endpoints: $($analysis.Summary.TotalEndpoints)
Unreachable Endpoints: $($analysis.Summary.UnreachableEndpoints)
Valid Certificates: $($analysis.Summary.ValidCertificates)
Invalid Certificates: $($analysis.Summary.InvalidCertificates) (Expired Certificates $($analysis.Summary.ExpiredCertificates)/$($analysis.Summary.InvalidCertificates))

$separator
$separator

Detailed Endpoint Analysis:
-------------------------

"@
	
	# Process endpoints with new formatting
	foreach ($endpoint in $analysis.Endpoints)
	{
		$report += "$separator$script:CRLF"
		
		# Add target and IP addresses
		$ipInfo = if ($endpoint.IPs) { " / " + ($endpoint.IPs -join " / ") }
		else { "" }
		$report += "== Target: $($endpoint.Target)$ipInfo$script:CRLF"
		
		if ($endpoint.Status -eq "ERROR")
		{
			$report += "Status: $($endpoint.Error)$script:CRLF"
		}
		elseif ($endpoint.Status -eq "Invalid Certificate")
		{
			$report += "Status: Invalid Certificate$script:CRLF"
			if ($endpoint.CertIssuer)
			{
				$report += "Certificate Issuer: $($endpoint.CertIssuer)$script:CRLF"
			}
			if ($endpoint.ValidationMessage)
			{
				$report += "Error: $($endpoint.ValidationMessage)$script:CRLF"
			}
		}
		else
		{
			if ($endpoint.CertIssuer)
			{
				$report += "Certificate Issuer: $($endpoint.CertIssuer)$script:CRLF"
			}
		}
		$report += "$script:CRLF"
	}
	
	$report += "$separator$script:CRLF$separator$script:CRLF$script:CRLF"
	
	# Add TLS Protocol Support Summary
	$report += @"
TLS Protocol Support Summary:
-------------------
TLS 1.3: $($analysis.Summary.TLS13Support) out of $($analysis.Summary.TotalEndpoints) endpoints
TLS 1.2: $($analysis.Summary.TLS12Support) out of $($analysis.Summary.TotalEndpoints) endpoints
TLS 1.1: $($analysis.Summary.TLS11Support) out of $($analysis.Summary.TotalEndpoints) endpoints
TLS 1.0: $($analysis.Summary.TLS10Support) out of $($analysis.Summary.TotalEndpoints) endpoints
"@
	
	# Save report
	$report | Out-File -FilePath $SummaryOutputFile -Encoding UTF8 -Force
}
#endregion Main SSL Testing Function

#endregion SSL Configuration Testing Functions


function Create-Folder($path) # Create the entire Folder path if missing
{
	Write-Verbose "Resolving the path: $path"
	$path = [System.IO.Path]::GetFullPath($path)
	$parentPath = Split-Path $path -Parent
	$showMessage = -NOT (Test-Path $parentPath) # Only show message if parent doesn't exist
	
	foreach ($SubFolder in $path.split('\'))
	{
		$foldPath += ($SubFolder + '\')
		
		try
		{
			if (-NOT (Test-Path $foldPath))
			{
				if ($showMessage)
				{
					Write-Console -MessageSegments @(
						@{ Text = "Creating folder structure: "; ForegroundColor = "DarkYellow" },
						@{ Text = "$path"; ForegroundColor = "DarkCyan" }
					)
					$showMessage = $false # Only show message once
				}
				Write-Verbose "Creating the directory: $path"
				New-Item -ItemType Directory -Path $foldPath -ErrorAction Stop | Out-Null
			}
		}
		catch
		{
			Write-Console -Text "Unable to create directory - $path`: $_" -ForegroundColor Red -BackgroundColor Black
		}
	}
}

<#
	.SYNOPSIS
		Function to assist with copying files and directories
	
	.DESCRIPTION
		Assists with copying files while outputting what its doing to the console. Creates directories if needed for nested items.
	
	.PARAMETER SourcePath
		The source path to copy.
	
	.PARAMETER DestinationFolder
		The destination path to copy.
	
	.PARAMETER changeFileName
		Add date to filename in output.
	
	.PARAMETER Quiet
		Do not output anything to the console.
	
	.EXAMPLE
		PS C:\> Copy-File -SourcePath $value1 -DestinationFolder 'Value2'
	
	.NOTES
		Additional information about the function.
#>
function Copy-File
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[Alias('Path')]
		[array]$SourcePath,
		[Parameter(Mandatory = $true)]
		[Alias('DestinationPath', 'Destination')]
		[string]$DestinationFolder,
		[switch]$changeFileName,
		[switch]$Quiet,
		[int]$MostRecentFileCount
	)
	
	# Handle destination path
	$DestinationFolder = [System.IO.Path]::GetFullPath($DestinationFolder)
	
	# If destination ends with a file name (contains extension), use its directory as the destination folder
	if ([System.IO.Path]::HasExtension($DestinationFolder))
	{
		$DestinationFile = $DestinationFolder
		$DestinationFolder = [System.IO.Path]::GetDirectoryName($DestinationFile)
		Create-Folder -path $DestinationFolder
		
		# Handle single file copy with specific destination name
		if ($SourcePath.Count -eq 1 -and (Test-Path $SourcePath[0] -PathType Leaf))
		{
			try
			{
				Copy-Item -Path $SourcePath[0] -Destination $DestinationFile -Force -ErrorAction Stop
				if ($Quiet)
				{
					Write-Verbose "Copying file: $($SourcePath[0]) -> $DestinationFile"
				}
				else
				{
					Write-Console -MessageSegments @(
						@{ Text = "Copying file: "; ForegroundColor = 'Green' },
						@{ Text = $($SourcePath[0]); ForegroundColor = 'DarkCyan' }
						@{ Text = " -> " }
						@{ Text = $DestinationFile; ForegroundColor = 'DarkCyan' }
					)
				}
				return
			}
			catch
			{
				if ($Quiet)
				{
					Write-Verbose "Error copying file $($SourcePath[0]) : $($_.Exception.Message)"
				}
				else
				{
					Write-Console -Text "Error copying file $($SourcePath[0]) : $($_.Exception.Message)" -ForegroundColor Yellow
				}
				return
			}
		}
	}
	
	foreach ($Source in $SourcePath)
	{
		# Handle wildcards by resolving them to actual file paths
		$resolvedPaths = @()
		try
		{
			if ($Source -match '\*')
			{
				# Get the parent path and file pattern
				$parentPath = Split-Path $Source
				$pattern = Split-Path $Source -Leaf
				
				# If parentPath is empty, use current directory
				if ([string]::IsNullOrEmpty($parentPath))
				{
					$parentPath = '.'
				}
				
				# Resolve the wildcard pattern
				$resolvedPaths = Get-ChildItem -Path $parentPath -Filter $pattern | Select-Object -ExpandProperty FullName
				
				if ($resolvedPaths.Count -eq 0)
				{
					if ($Quiet)
					{
						Write-Verbose "No files found matching pattern: $Source"
					}
					else
					{
						Write-Console -Text "No files found matching pattern: $Source" -ForegroundColor Gray
					}
					if (Test-Path $DestinationFolder)
					{
						$NotFoundFile = Join-Path -Path $DestinationFolder -ChildPath "NotFoundFiles.txt"
						Add-Content -Path $NotFoundFile -Value "No files found matching pattern: $Source`n"
					}
					continue
				}
			}
			else
			{
				$resolvedPaths = @($Source)
			}
		}
		catch
		{
			if ($Quiet)
			{
				Write-Verbose "Error resolving path $Source : $($_.Exception.Message)"
			}
			else
			{
				Write-Console -Text "Error resolving path $Source : $($_.Exception.Message)" -ForegroundColor Yellow
			}
			continue
		}
		
		foreach ($resolvedPath in $resolvedPaths)
		{
			if (Test-Path $resolvedPath -ErrorAction SilentlyContinue)
			{
				try
				{
					$SourceItem = Get-Item $resolvedPath -ErrorAction Stop
					
					if ($SourceItem.PSIsContainer)
					{
						# For directories, create the destination directory including the source folder name
						$lastFolderName = Split-Path $resolvedPath -Leaf
						$DestinationDir = Join-Path $DestinationFolder $lastFolderName
						
						if ($changeFileName)
						{
							$DateTime = (Get-Date).ToString('yyyy-MMM-dd_HH-mm')
							$DestinationDir = "$DestinationDir_$DateTime"
						}
						
						# Create the destination directory
						Create-Folder -path $DestinationDir
						
						try
						{
							# Copy the entire directory structure
							Copy-Item -Path $resolvedPath -Destination $DestinationFolder -Recurse -Force -ErrorAction Stop
							
							if ($Quiet)
							{
								Write-Verbose "Copying contents of directory: $resolvedPath -> $DestinationDir"
							}
							else
							{
								Write-Console -MessageSegments @(
									@{ Text = "Copying contents of directory: "; ForegroundColor = 'Green' },
									@{ Text = $resolvedPath; ForegroundColor = 'DarkCyan' }
									@{ Text = " -> " }
									@{ Text = $DestinationDir; ForegroundColor = 'DarkCyan' }
								)
							}
						}
						catch
						{
							if ($Quiet)
							{
								Write-Verbose "Error copying directory $resolvedPath : $($_.Exception.Message)"
							}
							else
							{
								Write-Console -Text "Error copying directory $resolvedPath : $($_.Exception.Message)" -ForegroundColor Yellow
							}
						}
					}
					else
					{
						# Handle single file copies
						$FileName = if ($changeFileName)
						{
							$DateTime = (Get-Date).ToString('yyyy-MMM-dd_HH-mm')
							$BaseName = [System.IO.Path]::GetFileNameWithoutExtension($SourceItem.Name)
							$Extension = [System.IO.Path]::GetExtension($SourceItem.Name)
							"$BaseName_$DateTime$Extension"
						}
						else
						{
							$SourceItem.Name
						}
						
						$DestinationFile = Join-Path -Path $DestinationFolder -ChildPath $FileName
						
						try
						{
							Copy-Item -Path $resolvedPath -Destination $DestinationFile -Force -ErrorAction Stop
							
							if ($Quiet)
							{
								Write-Verbose "Copying file $resolvedPath -> $DestinationFile"
							}
							else
							{
								Write-Console -Text "Copying file $resolvedPath -> $DestinationFile" -ForegroundColor Cyan
							}
						}
						catch
						{
							if ($Quiet)
							{
								Write-Verbose "Error copying file $resolvedPath : $($_.Exception.Message)"
							}
							else
							{
								Write-Console -Text "Error copying file $resolvedPath : $($_.Exception.Message)" -ForegroundColor Yellow
							}
						}
					}
				}
				catch
				{
					if ($Quiet)
					{
						Write-Verbose "Unable to access '$resolvedPath': $($_.Exception.Message)"
					}
					else
					{
						Write-Console -Text "Unable to access '$resolvedPath': $($_.Exception.Message)" -ForegroundColor Yellow
					}
					continue
				}
			}
			else
			{
				$NotFoundMsg = "Source path not found: $resolvedPath"
				if ($Quiet)
				{
					Write-Verbose $NotFoundMsg
				}
				else
				{
					Write-Console -Text $NotFoundMsg -ForegroundColor Gray
				}
				if (Test-Path $DestinationFolder)
				{
					$NotFoundFile = Join-Path -Path $DestinationFolder -ChildPath "NotFoundFiles.txt"
					Add-Content -Path $NotFoundFile -Value "$NotFoundMsg`n"
				}
				else
				{
					Write-Verbose "Unable to locate this destination folder, so doing nothing: $DestinationFolder"
				}
			}
		}
	}
}

function Try-Cmdlet($command, $outputfileName)
{
	Try
	{
		"$(Time-Stamp) [command]::($command) " | Out-File -Append $outputfileName
		& $command | Out-File -Append $outputfileName; "" >> $outputfileName
	}
	Catch { }
}

# Define a function to check the path and export registry data
function Get-RegistryData
{
	[CmdletBinding()]
	param
	(
		[string]$RegistryPath,
		[string]$OutputFile
	)
	
	if (Test-Path "Microsoft.PowerShell.Core\Registry::$RegistryPath")
	{
		# Use REG EXPORT to export the registry key
		REG EXPORT $RegistryPath $OutputFile /y | Out-Null
	}
	else
	{
		Write-Console -Text "Path not found: $RegistryPath" -ForegroundColor Gray
		"'$RegistryPath' Not present" | Out-File $OutputFile -Force
	}
}

function Write-ScriptProgress
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Activity,
		[string]$Status,
		[int]$Id,
		[switch]$Completed,
		[string]$CurrentOperation,
		[int]$ParentId,
		[ValidateRange(0, 100)]
		[int]$PercentComplete,
		[int]$SecondsRemaining,
		[int]$SourceId
	)
	
	if (-NOT $DontDisplayProgressBar)
	{
		# Create a hashtable to hold the parameters
		$params = @{
			Activity = $Activity + ": $PercentComplete`%"
		}
		
		# Add parameters to the hashtable if they are provided
		if ($Status) { $params.Status = $Status }
		
		if ($PSBoundParameters.ContainsKey('Id'))
		{
			$params.Id = $Id
		}
		
		if ($Completed.IsPresent)
		{
			$params.Completed = $true
		}
		
		if ($CurrentOperation)
		{
			$params.CurrentOperation = $CurrentOperation
		}
		
		if ($PSBoundParameters.ContainsKey('ParentId'))
		{
			$params.ParentId = $ParentId
		}
		
		if ($PSBoundParameters.ContainsKey('PercentComplete'))
		{
			$params.PercentComplete = $PercentComplete
		}
		
		if ($PSBoundParameters.ContainsKey('SecondsRemaining'))
		{
			$params.SecondsRemaining = $SecondsRemaining
		}
		
		if ($PSBoundParameters.ContainsKey('SourceId'))
		{
			$params.SourceId = $SourceId
		}
		
		# Call Write-Progress with all the parameters
		Write-Progress @params
	}
	else
	{
		return
	}
}

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


function Convert-SizeToString
{
	param (
		[long]$Size
	)
	
	if ($Size -ge 1TB)
	{
		return "{0:N2} TB" -f ($Size / 1TB)
	}
	elseif ($Size -ge 1GB)
	{
		return "{0:N2} GB" -f ($Size / 1GB)
	}
	elseif ($Size -ge 1MB)
	{
		return "{0:N2} MB" -f ($Size / 1MB)
	}
	elseif ($Size -ge 1KB)
	{
		return "{0:N2} KB" -f ($Size / 1KB)
	}
	else
	{
		return "{0} bytes" -f $Size
	}
}

#region Custom Get Child Item
function Get-DirectorySize
{
	param (
		[string]$Path
	)
	
	$totalSize = (Get-ChildItem -Force -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	return $totalSize -as [long] # Ensure it returns 0 if null
}

function Get-CustomChildItem
{
	param (
		[string]$Path = ".",
		[switch]$Recurse
	)
	
	# Calculate total size utilized in the directory
	$totalSize = Get-DirectorySize -Path $Path
	$utilized = Convert-SizeToString ($totalSize -as [long])
	
	# Output directory header
	Write-Output ""
	Write-Output "=============================================================================================="
	Write-Output "=============================================================================================="
	Write-Output ""
	Write-Output "    Directory: $Path ($utilized utilized)"
	Write-Output ""
	Write-Output ("{0,-7} {1,-22} {2,-15} {3,-22} {4}" -f "Mode", "LastWriteTime", "Size", "Type", "Name")
	Write-Output ("{0,-7} {1,-22} {2,-15} {3,-22} {4}" -f "----", "-------------", "------", "----", "----")
	
	# Get child items (non-recursive) and sort
	$items = Get-ChildItem -Force -LiteralPath $Path -ErrorAction SilentlyContinue | Sort-Object @{ Expression = 'LastWriteTime'; Descending = $true }, @{ Expression = 'Name'; Ascending = $true }
	
	foreach ($item in $items)
	{
		# Determine if hidden
		$isHidden = ($item.Attributes -band [System.IO.FileAttributes]::Hidden)
		
		if ($item.PSIsContainer)
		{
			# For directories, calculate their size
			$dirSize = Get-DirectorySize -Path $item.FullName
			$mode = "d" + ($item.Mode.Substring(1))
			$type = if ($isHidden) { "Directory (Hidden)" }
			else { "Directory" }
			$line = "{0,-7} {1,-22} {2,-15} {3,-22} {4}" -f $mode, $item.LastWriteTime.ToString("g"), (Convert-SizeToString $dirSize), $type, $item.Name
			Write-Output $line
		}
		else
		{
			# For files, display size
			$mode = $item.Mode
			$type = if ($isHidden) { "File (Hidden)" }
			else { "File" }
			$line = "{0,-7} {1,-22} {2,-15} {3,-22} {4}" -f $mode, $item.LastWriteTime.ToString("g"), (Convert-SizeToString $item.Length), $type, $item.Name
			Write-Output $line
		}
	}
	
	if ($Recurse)
	{
		# Recursively process subdirectories
		foreach ($item in $items)
		{
			if ($item.PSIsContainer)
			{
				Get-CustomChildItem -Path $item.FullName -Recurse
			}
		}
	}
}
#endregion Custom Get Child Item