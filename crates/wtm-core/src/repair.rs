//! Controlled system repair and network maintenance actions.

use std::os::windows::process::CommandExt;
use std::process::Command;

use serde::{Deserialize, Serialize};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsProvider {
    Automatic,
    Cloudflare,
    Quad9,
    Google,
    AdGuard,
    OpenDns,
}

impl DnsProvider {
    pub const ALL: [DnsProvider; 6] = [
        Self::Automatic,
        Self::Cloudflare,
        Self::Quad9,
        Self::Google,
        Self::AdGuard,
        Self::OpenDns,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Automatic => "Automatic (DHCP)",
            Self::Cloudflare => "Cloudflare (1.1.1.1 / 1.0.0.1)",
            Self::Quad9 => "Quad9 (9.9.9.9 / 149.112.112.112)",
            Self::Google => "Google (8.8.8.8 / 8.8.4.4)",
            Self::AdGuard => "AdGuard (94.140.14.14 / 94.140.15.15)",
            Self::OpenDns => "OpenDNS (208.67.222.222 / 208.67.220.220)",
        }
    }

    pub fn servers(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Automatic => None,
            Self::Cloudflare => Some(("1.1.1.1", "1.0.0.1")),
            Self::Quad9 => Some(("9.9.9.9", "149.112.112.112")),
            Self::Google => Some(("8.8.8.8", "8.8.4.4")),
            Self::AdGuard => Some(("94.140.14.14", "94.140.15.15")),
            Self::OpenDns => Some(("208.67.222.222", "208.67.220.220")),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "automatic" | "dhcp" => Some(Self::Automatic),
            "cloudflare" | "1.1.1.1" => Some(Self::Cloudflare),
            "quad9" | "9.9.9.9" => Some(Self::Quad9),
            "google" | "8.8.8.8" => Some(Self::Google),
            "adguard" => Some(Self::AdGuard),
            "opendns" => Some(Self::OpenDns),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetAdapterInfo {
    pub name: String,
    pub description: String,
    pub status: String,
    pub mac: String,
    pub link_speed: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway: String,
    pub dhcp_enabled: bool,
    pub dns_servers: Vec<String>,
    pub dns_dhcp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    SfcScan,
    DismRestoreHealth,
    FlushDns,
    RenewIp,
    NetworkReset,
    TimeSync,
    SetDns(DnsProvider),
    CreateRestorePoint,
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => String::new(),
    };

    if out.status.success() {
        Ok(if combined.is_empty() {
            format!("{program} completed successfully.")
        } else {
            combined
        })
    } else {
        let code = out.status.code().unwrap_or(-1);
        Err(if combined.is_empty() {
            format!("{program} exited with code {code} (administrator rights may be required).")
        } else {
            format!("{program} exited with code {code}:\n{combined}")
        })
    }
}

/// Runs a controlled system repair or network maintenance command.
pub fn run_repair(action: RepairAction) -> Result<String, String> {
    match action {
        RepairAction::SfcScan => run_cmd("sfc", &["/scannow"]),
        RepairAction::DismRestoreHealth => {
            run_cmd("DISM", &["/Online", "/Cleanup-Image", "/RestoreHealth"])
        }
        RepairAction::FlushDns => run_cmd("ipconfig", &["/flushdns"]),
        RepairAction::RenewIp => {
            let _ = run_cmd("ipconfig", &["/release"]);
            run_cmd("ipconfig", &["/renew"])
        }
        RepairAction::NetworkReset => {
            let mut log = Vec::new();
            for (prog, args) in [
                ("ipconfig", &["/flushdns"][..]),
                ("netsh", &["winsock", "reset"][..]),
                ("netsh", &["int", "ip", "reset"][..]),
            ] {
                match run_cmd(prog, args) {
                    Ok(out) => log.push(out),
                    Err(e) => log.push(format!("Warning: {e}")),
                }
            }
            Ok(log.join("\n\n"))
        }
        RepairAction::TimeSync => {
            let _ = run_cmd("net", &["start", "w32time"]);
            run_cmd("w32tm", &["/resync", "/force"])
        }
        RepairAction::SetDns(provider) => {
            let script = match provider.servers() {
                None => "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Set-DnsClientServerAddress -ResetServerAddresses".to_owned(),
                Some((p, s)) => format!(
                    "Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Set-DnsClientServerAddress -ServerAddresses ('{p}','{s}')"
                ),
            };
            run_cmd("powershell", &["-NoProfile", "-Command", &script])
                .map(|_| format!("DNS updated to {}.", provider.label()))
        }
        RepairAction::CreateRestorePoint => {
            let script = "Enable-ComputerRestore -Drive \"$env:SystemDrive\\\"; Checkpoint-Computer -Description 'RustWTM Restore Point' -RestorePointType 'MODIFY_SETTINGS'";
            run_cmd("powershell", &["-NoProfile", "-Command", script])
                .map(|_| "System restore point 'RustWTM Restore Point' created.".to_owned())
        }
    }
}

/// Queries active and available network adapters with IPv4/IPv6, gateway, MAC,
/// DHCP/manual IP mode, and DNS server configuration.
pub fn list_network_adapters() -> Result<Vec<NetAdapterInfo>, String> {
    let script = r#"
$adapters = Get-NetAdapter | ForEach-Object {
    $ifIdx = $_.ifIndex
    $ip4 = @(Get-NetIPAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' })
    $ip6 = @(Get-NetIPAddress -InterfaceIndex $ifIdx -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' })
    $ipIf = Get-NetIPInterface -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $gw = (Get-NetRoute -InterfaceIndex $ifIdx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    $dnsList = @($dns | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $dhcpVal = if ($ipIf) { $ipIf.Dhcp -eq 'Enabled' } else { $false }
    $dnsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)" -ErrorAction SilentlyContinue
    $dnsManual = $dnsReg -and -not [string]::IsNullOrWhiteSpace($dnsReg.NameServer)
    [PSCustomObject]@{
        name = [string]$_.Name
        description = [string]$_.InterfaceDescription
        status = [string]$_.Status
        mac = [string]$_.MacAddress
        link_speed = [string]$_.LinkSpeed
        ipv4 = @($ip4 | ForEach-Object { [string]"$($_.IPAddress)/$($_.PrefixLength)" })
        ipv6 = @($ip6 | ForEach-Object { [string]"$($_.IPAddress)/$($_.PrefixLength)" })
        gateway = [string]$gw
        dhcp_enabled = [bool]$dhcpVal
        dns_servers = $dnsList
        dns_dhcp = [bool](-not $dnsManual)
    }
}
@($adapters) | ConvertTo-Json -Depth 4
"#;
    let out = run_cmd("powershell", &["-NoProfile", "-Command", script])?;
    parse_adapters_json(&out)
}

fn parse_adapters_json(raw: &str) -> Result<Vec<NetAdapterInfo>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<NetAdapterInfo>>(trimmed).map_err(|e| e.to_string())
    } else {
        serde_json::from_str::<NetAdapterInfo>(trimmed)
            .map(|one| vec![one])
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_providers() {
        assert_eq!(
            DnsProvider::parse("cloudflare"),
            Some(DnsProvider::Cloudflare)
        );
        assert_eq!(DnsProvider::parse("AUTO"), Some(DnsProvider::Automatic));
        assert_eq!(DnsProvider::parse("unknown"), None);
    }

    #[test]
    fn parses_single_or_array_adapter_json() {
        let single = r#"{"name":"Wi-Fi","description":"Intel","status":"Up","mac":"AA-BB","link_speed":"1 Gbps","ipv4":["192.168.1.10/24"],"ipv6":[],"gateway":"192.168.1.1","dhcp_enabled":true,"dns_servers":["1.1.1.1"],"dns_dhcp":false}"#;
        let parsed = parse_adapters_json(single).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "Wi-Fi");
        assert!(parsed[0].dhcp_enabled);
        assert!(!parsed[0].dns_dhcp);
    }
}
