# Add routes to TURN servers via default gateway (Windows)
$gateway = Get-NetRoute `
    -DestinationPrefix "0.0.0.0/0" `
    | Sort-Object RouteMetric `
    | Select-Object -First 1 -ExpandProperty NextHop

if (-not $gateway) {
    Write-Error "Cannot detect default gateway"
    exit 1
}

Write-Host "Default gateway: $gateway"

$input | ForEach-Object {
    $addr = $_.Trim()
    if ($addr -eq "") { return }
    Write-Host "Adding route to $addr via $gateway"
    New-NetRoute `
        -DestinationPrefix "$addr/32" `
        -NextHop $gateway `
        -PolicyStore ActiveStore `
        -ErrorAction Stop
}
