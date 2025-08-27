function Import-HawkAzureAppCredentials {
    <#
    .SYNOPSIS
    Import Azure App credentials from CSV file
    
    .DESCRIPTION
    Helper function to validate and import Azure App credentials for Hawk authentication
    
    .PARAMETER CsvPath
    Path to CSV file containing Azure App credentials
    
    .PARAMETER ClientName
    Specific client name to return (optional)
    
    .EXAMPLE
    $creds = Import-HawkAzureAppCredentials -CsvPath ".\creds.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $false)]
        [string]$ClientName
    )
    
    try {
        $azureApps = Import-Csv -Path $CsvPath
        
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
        
        if ($ClientName) {
            $result = $azureApps | Where-Object { $_.Client -eq $ClientName }
            if (-not $result) {
                throw "Client '$ClientName' not found. Available: $($azureApps.Client -join ', ')"
            }
            return $result
        } else {
            return $azureApps
        }
        
    } catch {
        throw "Failed to import Azure App credentials: $($_.Exception.Message)"
    }
}
