Function Start-HawkTenantInvestigation {
    <#
    .SYNOPSIS
        Performs a comprehensive tenant-wide investigation using Hawk's automated data collection capabilities.

    .DESCRIPTION
        Start-HawkTenantInvestigation automates the collection and analysis of Microsoft 365 tenant-wide security data.
        It gathers information about tenant configuration, security settings, administrative changes, and potential security
        issues across the environment.

        The command can run in either interactive mode (default) or non-interactive mode. Interactive mode is used
        when no parameters are provided, while non-interactive mode is automatically enabled when any parameter is
        specified. In interactive mode, it prompts for necessary information such as date ranges and output location.

        Data collected includes:
        - Tenant configuration settings
        - eDiscovery configuration and logs
        - Administrative changes and permissions
        - Domain activities
        - Application consents and credentials
        - Exchange Online administrative activities

        All collected data is stored in a structured format for analysis, with suspicious findings highlighted
        for investigation.

    .PARAMETER StartDate
        The beginning date for the investigation period. When specified, must be used with EndDate.
        Cannot be later than EndDate and the date range cannot exceed 365 days.
        Providing this parameter automatically enables non-interactive mode.
        Format: MM/DD/YYYY

    .PARAMETER EndDate
        The ending date for the investigation period. When specified, must be used with StartDate.
        Cannot be in the future and the date range cannot exceed 365 days.
        Providing this parameter automatically enables non-interactive mode.
        Format: MM/DD/YYYY

    .PARAMETER DaysToLookBack
        Alternative to StartDate/EndDate. Specifies the number of days to look back from the current date.
        Must be between 1 and 365. Cannot be used together with StartDate.
        Providing this parameter automatically enables non-interactive mode.

    .PARAMETER FilePath
        The file system path where investigation results will be stored.
        Required in non-interactive mode. Must be a valid file system path.
        Providing this parameter automatically enables non-interactive mode.

    .PARAMETER SkipUpdate
        Switch to bypass the automatic check for Hawk module updates.
        Useful in automated scenarios or air-gapped environments.
        Providing this parameter automatically enables non-interactive mode.

    .PARAMETER AzureAppCsvPath
        Path to CSV file containing Azure App credentials for authentication.

    .PARAMETER AzureAppClientName
        Name of the Azure App client to use from the CSV file.

    .PARAMETER UseAzureApp
        Switch to enable Azure App authentication mode.

    .PARAMETER Confirm
        Prompts you for confirmation before executing each investigation step.
        By default, confirmation prompts appear for operations that could collect sensitive data.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not executed.
        Use this parameter to understand which investigation steps would be performed without actually collecting data.

    .OUTPUTS
        Creates multiple CSV and JSON files containing investigation results.
        All outputs are placed in the specified FilePath directory.
        See individual cmdlet help for specific output details.

    .EXAMPLE
        Start-HawkTenantInvestigation

        Runs a tenant investigation in interactive mode, prompting for date range and output location.

    .EXAMPLE
        Start-HawkTenantInvestigation -DaysToLookBack 30 -FilePath "C:\Investigation"

        Performs a tenant investigation looking back 30 days from today, saving results to C:\Investigation.
        Runs in non-interactive mode because parameters were specified.

    .EXAMPLE
        Start-HawkTenantInvestigation -StartDate "01/01/2024" -EndDate "01/31/2024" -FilePath "C:\Investigation" -SkipUpdate

        Investigates tenant activity for January 2024, saving results to C:\Investigation.
        Skips the update check. Runs in non-interactive mode because parameters were specified.

    .EXAMPLE
        Start-HawkTenantInvestigation -UseAzureApp -AzureAppCsvPath "C:\creds.csv" -AzureAppClientName "SOC Client" -DaysToLookBack 30 -FilePath "C:\Investigation"

        Runs investigation using Azure App authentication with 30-day lookback.

    .EXAMPLE
        Start-HawkTenantInvestigation -WhatIf

        Shows what investigation steps would be performed without actually executing them.
        Useful for understanding the investigation process or validating parameters.

    .LINK
        https://hawkforensics.io

    .LINK
        https://github.com/T0pCyber/hawk
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [int]$DaysToLookBack,
        [string]$FilePath,
        [switch]$SkipUpdate,
        [Parameter(Mandatory = $false)]
        [string]$AzureAppCsvPath,
        [Parameter(Mandatory = $false)]  
        [string]$AzureAppClientName,
        [Parameter(Mandatory = $false)]
        [switch]$UseAzureApp
    )

    begin {
        $NonInteractive = Test-HawkNonInteractiveMode -PSBoundParameters $PSBoundParameters

        # Handle Azure App authentication AFTER $NonInteractive is defined
        $azureAppUsed = $false
        if ($UseAzureApp -or $AzureAppCsvPath -or $AzureAppClientName) {
            Write-Output "[HAWK] Azure App authentication detected, initializing..."
            
            try {
                # Validate CSV path
                if ([string]::IsNullOrEmpty($AzureAppCsvPath)) {
                    throw "AzureAppCsvPath is required when using Azure App authentication"
                }
                
                if (-not (Test-Path $AzureAppCsvPath)) {
                    throw "Azure App CSV file not found: $AzureAppCsvPath"
                }
                
                if ([string]::IsNullOrEmpty($AzureAppClientName)) {
                    throw "AzureAppClientName is required when using Azure App authentication"
                }
                
                # Import and validate CSV
                $azureApps = Import-Csv -Path $AzureAppCsvPath
                $requiredColumns = @('Client', 'Tenant ID', 'Client ID', 'Key Value', 'Expiry')
                
                if ($azureApps.Count -eq 0) {
                    throw "CSV file is empty"
                }
                
                $csvColumns = $azureApps[0].PSObject.Properties.Name
                foreach ($column in $requiredColumns) {
                    if ($column -notin $csvColumns) {
                        throw "Missing required column: $column"
                    }
                }
                
                # Find the specified client
                $selectedApp = $azureApps | Where-Object { $_.Client -eq $AzureAppClientName }
                if (-not $selectedApp) {
                    throw "Client '$AzureAppClientName' not found in CSV. Available clients: $($azureApps.Client -join ', ')"
                }
                
                Write-Output "[HAWK] Connecting with Azure App: $AzureAppClientName"
                Write-Output "[HAWK] Tenant ID: $($selectedApp.'Tenant ID')"
                
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
                Write-Output "[HAWK] Connecting to Microsoft Graph..."
                Connect-MgGraph -TenantId $selectedApp.'Tenant ID' -ClientSecretCredential $clientSecretCredential -NoWelcome
                
                # Verify Graph connection
                $context = Get-MgContext
                if ($context) {
                    Write-Output "[HAWK] Microsoft Graph connected successfully"
                    Write-Output "[HAWK]   Account: $($context.Account)"
                } else {
                    throw "Microsoft Graph connection failed"
                }
                
                # Connect to Exchange Online with access token (headless)
                Write-Output "[HAWK] Connecting to Exchange Online with access token..."
                try {
                    # Get organization domain - try different approaches
                    $organizationDomain = $selectedApp.'Tenant ID'
                    
                    # Try to get domains without filter (some tenants don't support filtering)
                    try {
                        $allDomains = Get-MgDomain
                        $primaryDomain = $allDomains | Where-Object { $_.IsInitial -eq $true }
                        if ($primaryDomain -and $primaryDomain.Id) {
                            $organizationDomain = $primaryDomain.Id
                            Write-Output "[HAWK] Using primary domain: $organizationDomain"
                        } else {
                            # Fallback to first .onmicrosoft.com domain
                            $onMicrosoftDomain = $allDomains | Where-Object { $_.Id -like "*.onmicrosoft.com" } | Select-Object -First 1
                            if ($onMicrosoftDomain) {
                                $organizationDomain = $onMicrosoftDomain.Id
                                Write-Output "[HAWK] Using onmicrosoft domain: $organizationDomain"
                            }
                        }
                    } catch {
                        Write-Warning "[HAWK] Could not retrieve domains, using tenant ID: $($_.Exception.Message)"
                    }
                    
                    # Get access token for Exchange Online
                    $tokenUrl = "https://login.microsoftonline.com/$($selectedApp.'Tenant ID')/oauth2/v2.0/token"
                    $tokenBody = @{
                        client_id = $selectedApp.'Client ID'
                        client_secret = $selectedApp.'Key Value'
                        scope = "https://outlook.office365.com/.default"
                        grant_type = "client_credentials"
                    }
                    
                    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
                    
                    if ($tokenResponse.access_token) {
                        # Connect to Exchange Online using access token
                        Connect-ExchangeOnline -AppId $selectedApp.'Client ID' -Organization $organizationDomain -AccessToken $tokenResponse.access_token -ShowProgress:$false -ShowBanner:$false -SkipLoadingFormatData:$true
                        
                        # Verify Exchange Online connection
                        $exoConnectionInfo = Get-ConnectionInformation
                        if ($exoConnectionInfo) {
                            Write-Output "[HAWK] Exchange Online connected successfully"
                            Write-Output "[HAWK]   Organization: $($exoConnectionInfo.Organization)"
                            Write-Output "[HAWK]   Auth Type: $($exoConnectionInfo.AuthenticationType)"
                        } else {
                            throw "Exchange Online connection verification failed"
                        }
                    } else {
                        throw "Failed to obtain Exchange Online access token"
                    }
                    
                } catch {
                    Write-Warning "[HAWK] Exchange Online connection failed: $($_.Exception.Message)"
                    Write-Output "[HAWK] Continuing with Microsoft Graph only (some data may be limited)..."
                    Write-Output "[HAWK] Note: Exchange Online requires 'Exchange Administrator' role assigned to the Azure App"
                }
                
                Write-Output "[HAWK] Azure App authentication completed successfully"
                $azureAppUsed = $true
                
                # Set up Hawk global object manually since we're bypassing Initialize-HawkGlobalObject
                if (-not $Global:Hawk) {
                    $Global:Hawk = @{}
                }
                
                # Set output path
                if ($FilePath) {
                    if (-not (Test-Path $FilePath)) {
                        New-Item -Path $FilePath -ItemType Directory -Force | Out-Null
                    }
                    $Global:Hawk.FilePath = $FilePath
                } else {
                    $Global:Hawk.FilePath = "C:\HawkOutput"
                    if (-not (Test-Path $Global:Hawk.FilePath)) {
                        New-Item -Path $Global:Hawk.FilePath -ItemType Directory -Force | Out-Null
                    }
                }
                
                # Set date range
                if ($DaysToLookBack) {
                    $Global:Hawk.EndDate = Get-Date
                    $Global:Hawk.StartDate = $Global:Hawk.EndDate.AddDays(-$DaysToLookBack)
                } elseif ($StartDate -and $EndDate) {
                    $Global:Hawk.StartDate = $StartDate
                    $Global:Hawk.EndDate = $EndDate
                } else {
                    $Global:Hawk.EndDate = Get-Date
                    $Global:Hawk.StartDate = $Global:Hawk.EndDate.AddDays(-7)
                }
                
                # Set additional global variables that Hawk functions expect
                $Global:Hawk.TenantId = $selectedApp.'Tenant ID'
                $Global:Hawk.ClientId = $selectedApp.'Client ID'
                $Global:Hawk.AzureAppMode = $true
                
                Write-Output "[HAWK] Investigation period: $($Global:Hawk.StartDate.ToString('yyyy-MM-dd')) to $($Global:Hawk.EndDate.ToString('yyyy-MM-dd'))"
                Write-Output "[HAWK] Output directory: $($Global:Hawk.FilePath)"
                
            } catch {
                Stop-PSFFunction -Message "Azure App authentication failed: $_" -EnableException $true
                return
            }
        }

        if ($NonInteractive) {
            $processedDates = Test-HawkDateParameter -PSBoundParameters $PSBoundParameters -StartDate $StartDate -EndDate $EndDate -DaysToLookBack $DaysToLookBack
            $StartDate = $processedDates.StartDate
            $EndDate = $processedDates.EndDate
    
            # Now call validation with updated StartDate/EndDate
            $validation = Test-HawkInvestigationParameter -StartDate $StartDate -EndDate $EndDate -DaysToLookBack $DaysToLookBack -FilePath $FilePath -NonInteractive
    
            if (-not $validation.IsValid) {
                foreach ($validationerror in $validation.ErrorMessages) {
                    Stop-PSFFunction -Message $validationerror -EnableException $true
                }
            }

            try {
                # Only run Initialize-HawkGlobalObject if Azure App was NOT used
                if (-not $azureAppUsed) {
                    if ($FilePath) {
                        Initialize-HawkGlobalObject -FilePath $FilePath
                    } else {
                        Initialize-HawkGlobalObject
                    }
                }
            }
            catch {
                Stop-PSFFunction -Message "Failed to initialize Hawk: $_" -EnableException $true
            }
        }
    }

    process {
        if (Test-PSFFunctionInterrupt) { return }

        # Check if Hawk object exists and is fully initialized (skip if Azure App was used)
        if (-not $azureAppUsed -and (Test-HawkGlobalObject)) {
            Initialize-HawkGlobalObject
        }
        $investigationStartTime = Get-Date
        Out-LogFile "Starting Tenant Investigation." -action
        Send-AIEvent -Event "CmdRun"
	
        # Wrap operations in ShouldProcess checks
        if ($PSCmdlet.ShouldProcess("Tenant Configuration", "Get configuration data")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantConfiguration." -action
            Get-HawkTenantConfiguration
        }
	
        if ($PSCmdlet.ShouldProcess("EDiscovery Configuration", "Get eDiscovery configuration")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEDiscoveryConfiguration." -action
            Get-HawkTenantEDiscoveryConfiguration
        }

        if ($PSCmdlet.ShouldProcess("EDiscovery Logs", "Get eDiscovery logs")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEDiscoveryLog." -action
            Get-HawkTenantEDiscoveryLog
        }
	
        if ($PSCmdlet.ShouldProcess("Admin Inbox Rule Creation Audit Log", "Search Admin Inbox Rule Creation")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantAdminInboxRuleCreation." -action
            Get-HawkTenantAdminInboxRuleCreation
        }
	
        if ($PSCmdlet.ShouldProcess("Admin Inbox Rule Modification Audit Log", "Search Admin Inbox Rule Modification")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantInboxRuleModification." -action
            Get-HawkTenantAdminInboxRuleModification
        }
	
        if ($PSCmdlet.ShouldProcess("Admin Inbox Rule Removal Audit Log", "Search Admin Inbox Rule Removal")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantAdminInboxRuleRemoval." -action
            Get-HawkTenantAdminInboxRuleRemoval
        }
	
        if ($PSCmdlet.ShouldProcess("Admin Inbox Rule Permission Change Audit Log", "Search Admin Inbox Permission Changes")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantAdminMailboxPermissionChange." -action
            Get-HawkTenantAdminMailboxPermissionChange
        }
		
        if ($PSCmdlet.ShouldProcess("Admin Email Forwarding Change Change Audit Log", "Search Admin Email Forwarding Changes")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantAdminEmailForwardingChange." -action
            Get-HawkTenantAdminEmailForwardingChange
        }
			
        if ($PSCmdlet.ShouldProcess("Domain Activity", "Get domain activity")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantDomainActivity." -action
            Get-HawkTenantDomainActivity
        }
	
        if ($PSCmdlet.ShouldProcess("RBAC Changes", "Get RBAC changes")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantRBACChange." -action
            Get-HawkTenantRBACChange
        }

        if ($PSCmdlet.ShouldProcess("Entra ID Audit Log", "Get Entra ID audit logs")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEntraIDAuditLog." -action
            Get-HawkTenantEntraIDAuditLog
        }
	
        if ($PSCmdlet.ShouldProcess("Entra ID App Audit Log", "Get Entra ID app audit logs")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEntraIDAppAuditLog." -action
            Get-HawkTenantEntraIDAppAuditLog
        }
	
        if ($PSCmdlet.ShouldProcess("Exchange Admins", "Get Exchange admin list")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEXOAdmin." -action
            Get-HawkTenantEXOAdmin
        }
	
        if ($PSCmdlet.ShouldProcess("Consent Grants", "Get consent grants")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantConsentGrant." -action
            Get-HawkTenantConsentGrant
        }

        if ($PSCmdlet.ShouldProcess("Risky Users", "Get Entra ID Risky Users")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantRiskyUsers." -action
            Get-HawkTenantRiskyUsers
        }

        if ($PSCmdlet.ShouldProcess("Risk Detections", "Get Entra ID Risk Detections")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantRiskDetections." -action
            Get-HawkTenantRiskDetections
        }
	
        if ($PSCmdlet.ShouldProcess("Entra ID Admins", "Get Entra ID admin list")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEntraIDAdmin." -action
            Get-HawkTenantEntraIDAdmin
        }
	
        if ($PSCmdlet.ShouldProcess("App and SPN Credentials", "Get credential details")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantAppAndSPNCredentialDetail." -action
            Get-HawkTenantAppAndSPNCredentialDetail
        }
	
        if ($PSCmdlet.ShouldProcess("Entra ID Users", "Get Entra ID user list")) {
            Write-Output ""
            Out-LogFile "Running Get-HawkTenantEntraIDUser." -action
            Get-HawkTenantEntraIDUser
        }
    }
    
    end {
        # Calculate end time and display summary
        $investigationEndTime = Get-Date
        Write-HawkInvestigationSummary -StartTime $investigationStartTime -EndTime $investigationEndTime -InvestigationType 'Tenant'
    }
}
