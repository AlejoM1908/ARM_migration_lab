param {
    [string]$privateIpv4,
    [string]$privateIpMask,
    [Int]$privateIpCidr,
    [string]$domainName,
    [string]$adminName,
    [string]$adminPassword
}

if (-not ($privateIpMask -or $privateIpCidr)) {
    throw "One of the subnets parameters 'privateIpMask' or 'privateIpCidr' must be specified."
}

if ($privateIpMask -and $privateIpCidr) {
    throw "Only one of the parameters 'privateIpMask' or 'privateIpCidr' can be specified."
}

if ($privateIpCidr) {
    if ($privateIpCidr -lt 8 -or $privateIpCidr -gt 30) {
        throw "The parameter 'privateIpCidr' must be between 8 and 30."
    }

    $privateIpMask = Convert-CidrToMask $privateIpCidr
}
elseif (-not (Check-ValidIpv4Address $privateIpv4)) {
    throw "The parameter 'privateIpv4' must be a valid IPv4 address."
}

function Check-ValidIpv4Address ($ip) {
    try {
        [IPAddress]$ip
        return $true
    }
    catch {
        return $false
    }
}

function Convert-CidrToMask($cidr) {
    $mask = ([Math]::Pow(2, $cidr) - 1) * ([Math]::Pow(2, 32 - $cidr))
    return ([IPAddress]$mask).IPAddressToString
}

function Get-NetworkAddress ($ip, $mask) {
    $network = ([IPAddress]$ip).address -band ([IPAddress]$mask).address
    return ([IPAddress]$network).Address
}

function Get-NextIpAddress ($ip) {
    $ip = [IPAddress]$ip
    $ipBytes = $ip.GetAddressBytes()
    $ipBytes[3]++
    return [IPAddress]$ipBytes
}

function Set-Ipv4Address($ip, $mask) {
    $nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    # Remove any existing IP address
    if (($nic | Get-NetIPConfiguration).IPv4Address.IPAddress) {
        $nic | Remove-NetIPAddress -AddressFamily IPv4 -Confirm:$false
    }

    # Remove any existing default gateway
    if (($nic | Get-NetIPConfiguration).IPv4DefaultGateway.NextHop) {
        $nic | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
    }

    # Set the gateway as the first Host IP in the subnet
    $gateway = Get-NextIpAddress (Get-NetworkAddress $ip $mask)

    # Set the IPv4 address using mask
    $nic | New-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -DefaultGateway $gateway -SubnetMask $mask

    # Deactivating IPv6
    Disble-NetAdapterBinding -InterfaceAlias $nic.Name -ComponentID ms_tcpip6
}

# Set the IPv4 address
Set-Ipv4Address $privateIpv4 $privateIpMask

# Join the domain using the given admin ADDS credentials
Add-Computer -DomainName $domainName -Credential $adminName -Password $adminPassword -Restart -Force