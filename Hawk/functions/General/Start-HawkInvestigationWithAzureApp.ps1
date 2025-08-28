function Start-HawkInvestigationWithAzureApp {
    <#
    .SYNOPSIS
    Start Hawk investigation using Azure App authentication
    
    .DESCRIPTION
    Connects to Microsoft Graph using Azure App credentials from CSV, then runs Hawk investigations
    
    .PARAMETER InvestigationType
    Type of investigation: Tenant or User
    
    .PARAMETER AzureAppCsvPath
    Path to CSV file with Azure App credentials
    
    .PARAMETER AzureAppClientName
    Name of Azure App client to use
    
    .PARAMETER UserPrincipalName
    UPN for user investigations
    
    .PARAMETER OutputPath
    Output directory for results
    
    .EXAMPLE
    Start-HawkInvestigationWithAzureApp -InvestigationType "Tenant" -AzureAppCsvPath ".\creds.csv" -AzureAppClientName "SOC Client" -OutputPath "C:\temp" -NonInteractive -DaysToLookBack 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Tenant", "User")]
        [string]$InvestigationType,
        
        [Parameter(Mandatory = $true)]
        [string]$AzureAppCsvPath,
        
        [Parameter(Mandatory = $true)]
        [string]$AzureAppClientName,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$NonInteractive,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysToLookBack,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$StartDate,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$EndDate
    )
    
    try {
        Write-Host "[HAWK] Starting $InvestigationType investigation with Azure App authentication" -ForegroundColor Cyan
        
        # Validate user parameter for user investigations
        if ($InvestigationType -eq "User" -and [string]::IsNullOrEmpty($UserPrincipalName)) {
            throw "UserPrincipalName is required for user investigations"
        }
        
        # Validate CSV path
        if (-not (Test-Path $AzureAppCsvPath)) {
            throw "Azure App CSV file not found: $AzureAppCsvPath"
        }
        
        # Import and validate CSV
        Write-Host "[HAWK] Loading Azure app credentials from CSV..." -ForegroundColor Gray
        $azureApps = Import-Csv -Path $AzureAppCsvPath
        
        # Validate CSV structure
        $requiredColumns = @('Client', 'Tenant ID', 'Client ID', 'Key Value', 'Expiry')
        if ($azureApps.Count -eq 0) {
            throw "CSV file is empty"
        }
        
        $csvColumns = $azureApps[0].PSObject.Properties.Name
        foreach ($column in $requiredColumns) {
            if ($column -notin $csvColumns) {
                throw "Missing required column: $column. Required columns: $($requiredColumns -join ', ')"
            }
        }
        
        # Find the specified client
        $selectedApp = $azureApps | Where-Object { $_.Client -eq $AzureAppClientName }
        if (-not $selectedApp) {
            throw "Client '$AzureAppClientName' not found in CSV. Available clients: $($azureApps.Client -join ', ')"
        }
        
        # Check expiry
        try {
            $expiryDate = [DateTime]::Parse($selectedApp.Expiry)
            if ($expiryDate -lt (Get-Date)) {
                Write-Warning "[HAWK] Credentials for '$AzureAppClientName' expired on $($selectedApp.Expiry)"
            } else {
                Write-Host "[HAWK] Credentials expire: $($selectedApp.Expiry)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "[HAWK] Could not parse expiry date: $($selectedApp.Expiry)"
        }
        
        Write-Host "[HAWK] Connecting with Azure App: $AzureAppClientName" -ForegroundColor Green
        Write-Host "[HAWK] Tenant ID: $($selectedApp.'Tenant ID')" -ForegroundColor Gray
        
        # Clean up existing connections
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            # Ignore cleanup errors
        }
        
        # Create secure credential for Microsoft Graph
        $secureClientSecret = ConvertTo-SecureString -String $selectedApp.'Key Value' -AsPlainText -Force
        $clientSecretCredential = New-Object System.Management.Automation.PSCredential($selectedApp.'Client ID', $secureClientSecret)
        
        # Connect to Microsoft Graph
        Write-Host "[HAWK] Connecting to Microsoft Graph..." -ForegroundColor Yellow
        
        Connect-MgGraph -TenantId $selectedApp.'Tenant ID' -ClientSecretCredential $clientSecretCredential -NoWelcome
        
        # Verify Graph connection
        $context = Get-MgContext
        if ($context) {
            Write-Host "[HAWK] ✓ Microsoft Graph connected successfully" -ForegroundColor Green
            Write-Host "[HAWK]   Account: $($context.Account)" -ForegroundColor Gray
        } else {
            throw "Microsoft Graph connection failed"
        }
        
        Write-Host "[HAWK] ✓ Azure App authentication completed successfully" -ForegroundColor Green
        
        # Start investigation - pass the date parameters through to Hawk
        switch ($InvestigationType) {
            "Tenant" {
                Write-Host "[HAWK] Starting tenant investigation..." -ForegroundColor Green
                
                # Build parameters for Start-HawkTenantInvestigation
                $hawkParams = @{}
                
                if ($OutputPath) {
                    if (-not (Test-Path $OutputPath)) {
                        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                    }
                    $hawkParams.FilePath = $OutputPath
                }
                
                if ($DaysToLookBack) {
                    $hawkParams.DaysToLookBack = $DaysToLookBack
                }
                
                if ($StartDate) {
                    $hawkParams.StartDate = $StartDate
                }
                
                if ($EndDate) {
                    $hawkParams.EndDate = $EndDate
                }
                
                # Always add SkipUpdate for automation
                $hawkParams.SkipUpdate = $true
                
                Write-Host "[HAWK] Calling Start-HawkTenantInvestigation with parameters: $($hawkParams.Keys -join ', ')" -ForegroundColor Gray
                Start-HawkTenantInvestigation @hawkParams
            }
            "User" {
                Write-Host "[HAWK] Starting user investigation for: $UserPrincipalName" -ForegroundColor Green
                
                # Build parameters for Start-HawkUserInvestigation
                $hawkParams = @{
                    UserPrincipalName = $UserPrincipalName
                }
                
                if ($OutputPath) {
                    if (-not (Test-Path $OutputPath)) {
                        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                    }
                    $hawkParams.FilePath = $OutputPath
                }
                
                if ($DaysToLookBack) {
                    $hawkParams.DaysToLookBack = $DaysToLookBack
                }
                
                if ($StartDate) {
                    $hawkParams.StartDate = $StartDate
                }
                
                if ($EndDate) {
                    $hawkParams.EndDate = $EndDate
                }
                
                # Always add SkipUpdate for automation
                $hawkParams.SkipUpdate = $true
                
                Write-Host "[HAWK] Calling Start-HawkUserInvestigation with parameters: $($hawkParams.Keys -join ', ')" -ForegroundColor Gray
                Start-HawkUserInvestigation @hawkParams
            }
        }
        
        Write-Host "[HAWK] Investigation completed successfully" -ForegroundColor Green
        
        # Show output location
        if ($OutputPath) {
            Write-Host "[HAWK] Results saved to: $OutputPath" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Error "[HAWK] Investigation failed: $($_.Exception.Message)"
        throw
    }
}
