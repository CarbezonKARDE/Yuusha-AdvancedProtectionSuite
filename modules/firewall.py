import subprocess
import winreg

def run_powershell(cmd):
    """Execute PowerShell commands for firewall modifications"""
    full_cmd = ["powershell", "-Command", cmd]
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else result.stderr

def get_firewall_rules():
    """Fetch firewall rules directly from Windows Registry"""
    rules = []
    active_rules = {}
    headers = ['DisplayName', 'Direction', 'Action', 'Enabled', 'Profile']
    
    PROFILE_MAP = {
        'Public': 0x4,
        'Private': 0x2,
        'Domain': 0x1,
        'Any': 0x7  # All profiles
    }

    try:
        key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    value_name, value_data, _ = winreg.EnumValue(key, i)
                    i += 1
                    
                    rule = {k: v for k, v in (item.split('=', 1) 
                           for item in value_data.split('|') if '=' in item)}
                    
                    # Extract basic information
                    display_name = rule.get('Name', 'Unnamed Rule')
                    direction = 'Inbound' if rule.get('Dir') == 'In' else 'Outbound'
                    action = 'Allow' if rule.get('Action') == 'Allow' else 'Block'
                    enabled = 'True' if rule.get('Active', 'false').lower() == 'true' else 'False'
                    
                    # Parse profile information
                    profile_str = rule.get('Profile', '')
                    profile_mask = 0
                    
                    if profile_str.isdigit():
                        profile_mask = int(profile_str)
                    else:
                        for part in profile_str.split(','):
                            clean_part = part.strip()
                            profile_mask |= PROFILE_MAP.get(clean_part, 0)
                    
                    profiles = []
                    if profile_mask & PROFILE_MAP['Domain']: profiles.append("Domain")
                    if profile_mask & PROFILE_MAP['Private']: profiles.append("Private")
                    if profile_mask & PROFILE_MAP['Public']: profiles.append("Public")
                    profile = ', '.join(profiles) if profiles else 'Any'

                    rules.append([display_name, direction, action, enabled, profile])

                    # Detect IP/Port rules
                    remote_ips = rule.get('RemoteIPs', '')
                    protocol = {'6': 'TCP', '17': 'UDP'}.get(rule.get('Protocol'), 'Any')
                    ports = rule.get('LPort', '') or rule.get('RPort', '')
                    
                    if remote_ips and remote_ips not in ['LocalSubnet', 'Any']:
                        active_rules[display_name] = {'type': 'IP', 'target': remote_ips}
                    elif ports or protocol != 'Any':
                        active_rules[display_name] = {'type': 'Port', 'protocol': protocol, 'port': ports}

                except OSError:
                    break

    except Exception as e:
        return [], headers, {}

    return rules, headers, active_rules

def block_ip(rule_name, target, direction="Inbound"):
    """Block specific IP address"""
    return run_powershell(
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction {direction} -RemoteAddress {target} -Action Block'
    )

def unblock_rule(rule_name):
    """Remove firewall rule by name"""
    return run_powershell(f'Remove-NetFirewallRule -DisplayName "{rule_name}"')

def block_port(rule_name, port, protocol="TCP", direction="Inbound"):
    """Block specific port"""
    return run_powershell(
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction {direction} -LocalPort {port} -Protocol {protocol} -Action Block'
    )