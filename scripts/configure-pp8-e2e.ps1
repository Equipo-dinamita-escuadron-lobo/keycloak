$ErrorActionPreference = 'Stop'

$baseUrl = $env:KEYCLOAK_ADMIN_URL
$realm = $env:KEYCLOAK_REALM
$tenantIds = @($env:PP8_TENANT_IDS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $baseUrl -or -not $realm -or $tenantIds.Count -eq 0 -or $tenantIds -contains '*') {
    throw 'KEYCLOAK_ADMIN_URL, KEYCLOAK_REALM and non-wildcard PP8_TENANT_IDS are required'
}

$token = $env:KEYCLOAK_ADMIN_TOKEN
if (-not $token) {
    if (-not $env:KEYCLOAK_ADMIN_USER -or -not $env:KEYCLOAK_ADMIN_PASSWORD) {
        throw 'Provide KEYCLOAK_ADMIN_TOKEN or admin user/password through the environment'
    }
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "$baseUrl/realms/master/protocol/openid-connect/token" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{ grant_type='password'; client_id='admin-cli'; username=$env:KEYCLOAK_ADMIN_USER; password=$env:KEYCLOAK_ADMIN_PASSWORD }
    $token = $tokenResponse.access_token
}
$headers = @{ Authorization = "Bearer $token" }

$clients = @{
    'treasury-service' = $env:TREASURY_OAUTH_CLIENT_SECRET
    'facture-service' = $env:FACTURE_OAUTH_CLIENT_SECRET
    'account-catalogue-service' = $env:ACCOUNT_CATALOGUE_OAUTH_CLIENT_SECRET
}
foreach ($entry in $clients.GetEnumerator()) {
    if (-not $entry.Value) { throw "Secret for $($entry.Key) must be supplied through the environment" }
    $matches = @(Invoke-RestMethod -Method Get -Uri "$baseUrl/admin/realms/$realm/clients?clientId=$($entry.Key)" -Headers $headers)
    if ($matches.Count -ne 1) { throw "Expected exactly one Keycloak client $($entry.Key)" }
    $client = $matches[0]
    Invoke-RestMethod -Method Put -Uri "$baseUrl/admin/realms/$realm/clients/$($client.id)" -Headers $headers `
        -ContentType 'application/json' -Body (@{ clientId=$entry.Key; enabled=$true; serviceAccountsEnabled=$true; publicClient=$false; secret=$entry.Value } | ConvertTo-Json)
    $serviceUser = Invoke-RestMethod -Method Get -Uri "$baseUrl/admin/realms/$realm/clients/$($client.id)/service-account-user" -Headers $headers
    $serviceUser | Add-Member -NotePropertyName attributes -NotePropertyValue @{ tenant_ids = $tenantIds } -Force
    Invoke-RestMethod -Method Put -Uri "$baseUrl/admin/realms/$realm/users/$($serviceUser.id)" -Headers $headers `
        -ContentType 'application/json' -Body ($serviceUser | ConvertTo-Json -Depth 12)
}

Write-Output 'PP8 technical clients configured; secret and tenant values were not printed.'
