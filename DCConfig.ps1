<#
.SYNOPSIS
    This script is used to configure a Domain Controller in an Active Directory environment.

.DESCRIPTION
    The script takes several parameters to configure the Domain Controller, including the private IP address, subnet mask or CIDR, 
    admin credentials, domain name, and safe mode password. It performs the following tasks:
    1. Validates the subnet parameters.
    2. Adds the required server roles (AD-Domain-Services and DNS).
    3. Promotes the server to a Domain Controller using the specified domain name and safe mode password.
    4. Sets the IPv4 address of the server.

.PARAMETER privateIpv4
    The private IPv4 address of the server.

.PARAMETER privateIpMask
    The subnet mask of the private IP address.

.PARAMETER privateIpCidr
    The CIDR notation of the private IP address.

.PARAMETER domainName
    The name of the domain.

.PARAMETER safeModePassword
    The password for the Directory Services Restore Mode (DSRM) administrator account.

.PARAMETER otherDomain
    The name of the other domain to make forward nd reverse lookup zones for and add a trust relationship with their domain.

.PARAMETER otherDomainIp
    The IP address of the other domain.

.EXAMPLE
    .\DCConfig.ps1 -privateIpv4 "192.168.1.10" -privateIpMask "255.255.255.0" -domainName "example.com" -safeModePassword "DSRM@P@ssw0rd" -otherDomain "other.com" -otherDomainIp "192.168.2.10"

.NOTES
    This script requires administrative privileges to run.
#>

param(
    [string]$privateIpv4,
    [string]$privateIpMask,
    [Int]$privateIpCidr,
    [string]$domainName,
    [string]$safeModePassword
    [string]$otherDomain
    [string]$otherDomainIp
)

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

function Add-ServerRole($roleName) {
    Install-WindowsFeature -Name $roleName -IncludeManagementTools -IncludeAllSubFeature
}

function Create-NewDomainController($domainName, $safeModePassword) {
    Install-ADDSForest -DomainName $domainName -SafeModeAdministratorPassword (ConvertTo-SecureString $safeModePassword -AsPlainText -Force) -Force -NoGlobalCatalog:$false -InstallDns:$true -createDnsDelegation:$false
    -NTDSPath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL"
    -NoRebootOnCompletion:$true
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

function Get-NextIpAddress ($ip, $count = 1) {
    $ip = [IPAddress]$ip
    $ipBytes = $ip.GetAddressBytes()
    $nextIps = @()

    for ($i = 1; $i -le $count; $i++) {
        $ipBytes[3]++
        $nextIps += [IPAddress]$ipBytes
    }

    return $nextIps
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

    # Set the IPv4 address using mask and DNS to loopback
    $nic | New-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -DefaultGateway $gateway -SubnetMask $mask -ServerAddresses "127.0.0.1", "1.1.1.1", $otherDomainIp

    # Deactivating IPv6
    Disble-NetAdapterBinding -InterfaceAlias $nic.Name -ComponentID ms_tcpip6
}

# Install ADDS and DNS roles
Add-ServerRole "AD-Domain-Services"
Add-ServerRole "DNS"

# Promote the server to a Domain Controller
Create-NewDomainController $domainName $safeModePassword

# Create a Forward Lookup Zone for the other domain


# Set the IPv4 address
Set-Ipv4Address $privateIpv4 $privateIpMask

# Restart the server to apply changes
Restart-Computer -Force