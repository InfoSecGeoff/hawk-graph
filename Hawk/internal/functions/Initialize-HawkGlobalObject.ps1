Function Initialize-HawkGlobalObject {
    <#
    .SYNOPSIS
        Initializes the Hawk global object with authentication and configuration settings.

    .DESCRIPTION
        Initialize-HawkGlobalObject sets up the global Hawk object that contains authentication details,
        configuration settings, and other data used by Hawk investigation functions.
        
        This function now supports both interactive authentication and Azure app registration authentication
        for automated/scripted scenarios commonly used in SOC environments.

    .PARAMETER Force
        Switch to force re-initialization even if a global object already exists.

    .PARAMETER FilePath
        Specifies the output directory for investigation files.
        Default is the current working directory.

    .PARAMETER Encoding
        Specifies the encoding for output files.
        Valid values: ASCII, UTF8, UTF7, UTF32, Unicode, BigEndianUnicode, Default, OEM
        Default is UTF8.

    .PARAMETER VerboseLogging
        Switch to enable verbose logging output.

    .PARAMETER SkipTenantConnection
        Switch to skip establishing tenant-level connections.
        Useful when only performing user-specific investigations.

    .PARAMETER SkipExchangeConnection
        Switch to skip establishing Exchange Online connections.
        Note: This will limit the data that can be collected.

    .PARAMETER SkipAzureConnection
        Switch to skip establishing Azure AD/Entra ID connections.
        Note: This will limit the data that can be collected.

    .PARAMETER UseAppAuthentication
        Switch to use Azure app registration authentication instead of interactive authentication.
        When enabled, requires TenantId, ClientId, and ClientSecret parameters.

    .PARAMETER TenantId
        Azure tenant ID (GUID) for app authentication.
        Required when UseAppAuthentication is specified.

    .PARAMETER ClientId
        Azure app registration client ID (GUID) for app authentication.
        Required when UseAppAuthentication is specified.

    .PARAMETER ClientSecret
        Azure app registration client secret for app authentication.
        Required when UseAppAuthentication is specified.
        Should be passed as a SecureString for security.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for certificate-based app authentication.
        Alternative to ClientSecret for app authentication.

    .PARAMETER Scopes
        Array of Microsoft Graph scopes to request during authentication.
        Default scopes include common permissions needed for Hawk investigations.

    .EXAMPLE
        Initialize-HawkGlobalObject
        
        Initializes Hawk with interactive authentication (original behavior).

    .EXAMPLE
        Initialize-HawkGlobalObject -UseAppAuthentication -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret $SecureSecret
        
        Initializes Hawk using Azure app registration authentication for automated scenarios.

    .EXAMPLE
        $SecretString = ConvertTo-SecureString "your-client-secret" -AsPlainText -Force
        Initialize-HawkGlobalObject -UseAppAuthentication -TenantId "tenant-guid" -ClientId "client-guid" -ClientSecret $SecretString -FilePath "C:\HawkOutput"
        
        Initializes Hawk with app authentication and specifies output directory.

    .EXAMPLE
        Initialize-HawkGlobalObject -UseAppAuthentication -TenantId "tenant-guid" -ClientId "client-guid" -CertificateThumbprint "ABC123..." -VerboseLogging
        
        Initializes Hawk using certificate-based app authentication with verbose logging.

    .NOTES
        For app authentication, ensure your Azure app registration has the following permissions:
        - AuditLog.Read.All
        - Directory.Read.All
        - Reports.Read.All
        - User.Read.All
        - Mail.Read
        - SecurityEvents.Read.All
        
        Author: Modified for SOC automation scenarios
        Version: Enhanced for Azure App Authentication
    #>

    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [switch]$Force,
        
        [string]$FilePath = (Get-Location).Path,
        
        [ValidateSet('ASCII', 'UTF8', 'UTF7', 'UTF32', 'Unicode', 'BigEndianUnicode', 'Default', 'OEM')]
        [string]$Encoding = 'UTF8',
        
        [switch]$VerboseLogging,
        
        [switch]$SkipTenantConnection,
        
        [switch]$SkipExchangeConnection,
        
        [switch]$SkipAzureConnection,
        
        # App Authentication Parameters
        [Parameter(ParameterSetName = 'AppAuth')]
        [switch]$UseAppAuthentication,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'AppAuth')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'AppAuth')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ClientId,
        
        [Parameter(ParameterSetName = 'AppAuth')]
        [SecureString]$ClientSecret,
        
        [Parameter(ParameterSetName = 'AppAuth')]
        [string]$CertificateThumbprint,
        
        [string[]]$Scopes = @(
            'AuditLog.Read.All',
            'Directory.Read.All', 
            'Reports.Read.All',
            'User.Read.All',
            'Mail.Read',
            'SecurityEvents.Read.All',
            'Organization.Read.All'
        )
    )

    begin {
        Write-Host "Initializing Hawk Global Object..." -ForegroundColor Green
        
        # Validate app authentication parameters
        if ($UseAppAuthentication) {
            if (-not $ClientSecret -and -not $CertificateThumbprint) {
                throw "When using app authentication, either ClientSecret or CertificateThumbprint must be provided."
            }
            
            if ($ClientSecret -and $CertificateThumbprint) {
                Write-Warning "Both ClientSecret and CertificateThumbprint provided. Using CertificateThumbprint."
                $ClientSecret = $null
            }
        }
    }

    process {
        try {
            # Check if global object exists and handle Force parameter
            if ($Global:HawkGlobalObject -and -not $Force) {
                Write-Host "Hawk Global Object already exists. Use -Force to reinitialize." -ForegroundColor Yellow
                return $Global:HawkGlobalObject
            }

            # Initialize the global object
            $Global:HawkGlobalObject = [PSCustomObject]@{
                FilePath = $FilePath
                Encoding = $Encoding
                VerboseLogging = $VerboseLogging
                AuthenticationMethod = if ($UseAppAuthentication) { 'AppRegistration' } else { 'Interactive' }
                TenantId = $TenantId
                ClientId = $ClientId
                Scopes = $Scopes
                StartTime = Get-Date
                Connections = @{
                    MicrosoftGraph = $false
                    ExchangeOnline = $false
                    AzureAD = $false
                }
                OutputDirectory = $null
                InvestigationName = $null
            }

            # Create output directory structure
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $investigationFolder = "Hawk_Investigation_$timestamp"
            $outputPath = Join-Path $FilePath $investigationFolder
            
            if (-not (Test-Path $outputPath)) {
                New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
                Write-Host "Created investigation directory: $outputPath" -ForegroundColor Green
            }
            
            $Global:HawkGlobalObject.OutputDirectory = $outputPath
            $Global:HawkGlobalObject.InvestigationName = $investigationFolder

            # Authentication Section
            Write-Host "Establishing connections..." -ForegroundColor Cyan

            # Microsoft Graph Authentication
            if (-not $SkipAzureConnection) {
                try {
                    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
                    
                    if ($UseAppAuthentication) {
                        # App Registration Authentication
                        if ($CertificateThumbprint) {
                            # Certificate-based authentication
                            Write-Host "Using certificate-based app authentication..." -ForegroundColor Cyan
                            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome
                        }
                        else {
                            # Client Secret authentication
                            Write-Host "Using client secret app authentication..." -ForegroundColor Cyan
                            $ClientSecretCredential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome
                        }
                    }
                    else {
                        # Interactive Authentication (original behavior)
                        Write-Host "Using interactive authentication..." -ForegroundColor Cyan
                        Connect-MgGraph -Scopes $Scopes -NoWelcome
                    }
                    
                    # Verify connection
                    $context = Get-MgContext
                    if ($context) {
                        $Global:HawkGlobalObject.Connections.MicrosoftGraph = $true
                        $Global:HawkGlobalObject.TenantId = $context.TenantId
                        Write-Host "✓ Microsoft Graph connected successfully" -ForegroundColor Green
                        Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
                        Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
                        Write-Host "  Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
                    $Global:HawkGlobalObject.Connections.MicrosoftGraph = $false
                }
            }

            # Exchange Online Authentication (if Graph connection successful and not skipped)
            if ($Global:HawkGlobalObject.Connections.MicrosoftGraph -and -not $SkipExchangeConnection) {
                try {
                    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
                    
                    if ($UseAppAuthentication) {
                        # For app authentication, use the same credentials for Exchange Online
                        if ($CertificateThumbprint) {
                            Connect-ExchangeOnline -CertificateThumbprint $CertificateThumbprint -AppId $ClientId -Organization $TenantId -ShowProgress:$false
                        }
                        else {
                            # Note: Exchange Online with client secret requires specific setup
                            Write-Warning "Exchange Online with client secret requires certificate-based authentication. Skipping Exchange Online connection."
                            $Global:HawkGlobalObject.Connections.ExchangeOnline = $false
                        }
                    }
                    else {
                        # Interactive authentication for Exchange Online
                        Connect-ExchangeOnline -ShowProgress:$false
                    }
                    
                    # Verify Exchange Online connection
                    $exoSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.State -eq 'Opened' }
                    if ($exoSession) {
                        $Global:HawkGlobalObject.Connections.ExchangeOnline = $true
                        Write-Host "✓ Exchange Online connected successfully" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Failed to connect to Exchange Online: $($_.Exception.Message)"
                    $Global:HawkGlobalObject.Connections.ExchangeOnline = $false
                }
            }

            # Log connection summary
            Write-Host "`nConnection Summary:" -ForegroundColor Cyan
            Write-Host "  Microsoft Graph: $(if($Global:HawkGlobalObject.Connections.MicrosoftGraph){'✓ Connected'}else{'✗ Not Connected'})" -ForegroundColor $(if($Global:HawkGlobalObject.Connections.MicrosoftGraph){'Green'}else{'Red'})
            Write-Host "  Exchange Online: $(if($Global:HawkGlobalObject.Connections.ExchangeOnline){'✓ Connected'}else{'✗ Not Connected'})" -ForegroundColor $(if($Global:HawkGlobalObject.Connections.ExchangeOnline){'Green'}else{'Red'})

            # Create log file
            $logFile = Join-Path $outputPath "HawkInitialization.log"
            $logEntry = @"
Hawk Investigation Initialized: $(Get-Date)
Authentication Method: $($Global:HawkGlobalObject.AuthenticationMethod)
Tenant ID: $($Global:HawkGlobalObject.TenantId)
Output Directory: $($Global:HawkGlobalObject.OutputDirectory)
Microsoft Graph Connected: $($Global:HawkGlobalObject.Connections.MicrosoftGraph)
Exchange Online Connected: $($Global:HawkGlobalObject.Connections.ExchangeOnline)
"@
            $logEntry | Out-File -FilePath $logFile -Encoding UTF8

            Write-Host "`nHawk Global Object initialized successfully!" -ForegroundColor Green
            Write-Host "Investigation directory: $outputPath" -ForegroundColor Gray
            
            return $Global:HawkGlobalObject
        }
        catch {
            Write-Error "Failed to initialize Hawk Global Object: $($_.Exception.Message)"
            throw
        }
    }

    end {
        if ($VerboseLogging) {
            Write-Host "`nHawk Global Object Details:" -ForegroundColor Cyan
            $Global:HawkGlobalObject | Format-List
        }
    }
}

# Helper function to validate and retrieve stored credentials (for SOC automation scenarios)
Function Get-HawkStoredCredentials {
    <#
    .SYNOPSIS
        Retrieves stored Azure app credentials for Hawk investigations.
    
    .DESCRIPTION
        Helper function to securely retrieve stored Azure app registration credentials
        from various sources like Azure Key Vault, Windows Credential Manager, or
        environment variables for automated SOC workflows.
    
    .PARAMETER Source
        Source of the stored credentials: 'KeyVault', 'CredentialManager', 'Environment'
    
    .PARAMETER KeyVaultName
        Name of the Azure Key Vault (when using KeyVault source)
    
    .PARAMETER SecretName
        Name of the secret containing the client secret
    
    .EXAMPLE
        $creds = Get-HawkStoredCredentials -Source 'Environment'
        Initialize-HawkGlobalObject -UseAppAuthentication -TenantId $creds.TenantId -ClientId $creds.ClientId -ClientSecret $creds.ClientSecret
    #>
    
    [CmdletBinding()]
    param(
        [ValidateSet('KeyVault', 'CredentialManager', 'Environment')]
        [string]$Source = 'Environment',
        
        [string]$KeyVaultName,
        [string]$SecretName = 'HawkClientSecret'
    )
    
    switch ($Source) {
        'Environment' {
            $tenantId = $env:HAWK_TENANT_ID
            $clientId = $env:HAWK_CLIENT_ID
            $clientSecret = $env:HAWK_CLIENT_SECRET
            
            if ($clientSecret) {
                $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
            }
            
            return @{
                TenantId = $tenantId
                ClientId = $clientId
                ClientSecret = $secureSecret
            }
        }
        
        'CredentialManager' {
            # Implementation for Windows Credential Manager
            # Requires CredentialManager PowerShell module
            try {
                $storedCred = Get-StoredCredential -Target "HawkAzureApp"
                return @{
                    TenantId = $env:HAWK_TENANT_ID
                    ClientId = $storedCred.UserName
                    ClientSecret = $storedCred.Password
                }
            }
            catch {
                Write-Error "Failed to retrieve credentials from Credential Manager: $($_.Exception.Message)"
            }
        }
        
        'KeyVault' {
            # Implementation for Azure Key Vault
            # Requires Az.KeyVault module
            try {
                $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName
                return @{
                    TenantId = $env:HAWK_TENANT_ID
                    ClientId = $env:HAWK_CLIENT_ID
                    ClientSecret = $secret.SecretValue
                }
            }
            catch {
                Write-Error "Failed to retrieve credentials from Key Vault: $($_.Exception.Message)"
            }
        }
    }
}

# Example usage function for SOC automation
Function Start-HawkSOCInvestigation {
    <#
    .SYNOPSIS
        Simplified function for SOC analysts to start Hawk investigations with app authentication.
    
    .DESCRIPTION
        Wrapper function that simplifies the process of starting Hawk investigations
        in SOC environments using Azure app registration authentication.
    
    .PARAMETER TenantId
        Azure tenant ID
    
    .PARAMETER ClientId
        Azure app registration client ID
    
    .PARAMETER ClientSecret
        Azure app registration client secret (as SecureString)
    
    .PARAMETER InvestigationType
        Type of investigation: 'Tenant', 'User', or 'Both'
    
    .PARAMETER UserPrincipalName
        User to investigate (required when InvestigationType is 'User' or 'Both')
    
    .PARAMETER OutputPath
        Output directory for investigation files
    
    .PARAMETER DaysBack
        Number of days to look back for audit logs (default: 30)
    
    .EXAMPLE
        $secureSecret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
        Start-HawkSOCInvestigation -TenantId "tenant-guid" -ClientId "client-guid" -ClientSecret $secureSecret -InvestigationType "Tenant"
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret,
        
        [ValidateSet('Tenant', 'User', 'Both')]
        [string]$InvestigationType = 'Tenant',
        
        [string]$UserPrincipalName,
        
        [string]$OutputPath = "C:\HawkInvestigations",
        
        [int]$DaysBack = 30
    )
    
    try {
        # Initialize Hawk with app authentication
        Write-Host "Starting SOC investigation with app authentication..." -ForegroundColor Green
        
        Initialize-HawkGlobalObject -UseAppAuthentication -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -FilePath $OutputPath -VerboseLogging
        
        # Run investigations based on type
        switch ($InvestigationType) {
            'Tenant' {
                Write-Host "Starting tenant investigation..." -ForegroundColor Cyan
                Start-HawkTenantInvestigation -DaysToLookBack $DaysBack -FilePath $Global:HawkGlobalObject.OutputDirectory
            }
            
            'User' {
                if (-not $UserPrincipalName) {
                    throw "UserPrincipalName is required for user investigations"
                }
                Write-Host "Starting user investigation for $UserPrincipalName..." -ForegroundColor Cyan
                Start-HawkUserInvestigation -UserPrincipalName $UserPrincipalName -DaysToLookBack $DaysBack -FilePath $Global:HawkGlobalObject.OutputDirectory
            }
            
            'Both' {
                if (-not $UserPrincipalName) {
                    throw "UserPrincipalName is required when InvestigationType is 'Both'"
                }
                Write-Host "Starting comprehensive investigation..." -ForegroundColor Cyan
                Start-HawkTenantInvestigation -DaysToLookBack $DaysBack -FilePath $Global:HawkGlobalObject.OutputDirectory
                Start-HawkUserInvestigation -UserPrincipalName $UserPrincipalName -DaysToLookBack $DaysBack -FilePath $Global:HawkGlobalObject.OutputDirectory
            }
        }
        
        Write-Host "Investigation completed. Results saved to: $($Global:HawkGlobalObject.OutputDirectory)" -ForegroundColor Green
    }
    catch {
        Write-Error "SOC investigation failed: $($_.Exception.Message)"
        throw
    }
}
