## Quick Download
[https://aka.ms/MicrosoftSupportLogs](https://aka.ms/MicrosoftSupportLogs)

## About
This PowerShell script is crafted to streamline the collection and generation of diagnostic files for Microsoft Support on Windows systems. It captures an extensive range of data, including:

- Network connectivity checks
- Installed software updates
- Environmental variables
- System services
- Event logs
- And more..

All collected data is stored in the specified output folder (`C:\MicrosoftSupportLogs`).

### Key Features
- **System Prerequisites Check**: Ensures TLS 1.2 support and validates regional settings for Azure automation accounts.
- **File and Directory Management**: Handles the creation and organization of necessary directories.
- **Command Execution**: Runs system commands and captures their output for diagnostics.
- **Windows Updates Management**: Differentiates and handles updates, excluding Defender updates from the primary list but tracking the most recent ones.

### Usage
The script is a comprehensive diagnostic tool that facilitates the support process by gathering all relevant system information and logs. Note that data is not automatically uploaded; it requires manual submission to Microsoft Support.

This tool aims to simplify and enhance the efficiency of the diagnostic process for Microsoft Support, providing a thorough collection of system information necessary for troubleshooting.
