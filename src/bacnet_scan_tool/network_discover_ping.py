#!/usr/bin/env python3
# TODO move to discovery tool.
# TODO make it work with ubuntu also
"""
Network Discovery Module for BACnet Scanning

This module discovers networks and IPs using multiple methods:
1. Windows routing table analysis
2. Network interface scanning
3. ARP table analysis
4. Adjacent network discovery
5. Common private network ranges

Returns discovered responsive networks for BACnet scanning.
"""

import subprocess
import re
import ipaddress
import platform
import asyncio
import concurrent.futures
from typing import Dict, Set, List, Tuple


def get_windows_routed_networks(
        verbose: bool = True) -> Dict[str, Dict[str, str]]:
    """
    Returns a dictionary of routed IPv4 networks on Windows from netstat.exe -r.
    This includes all networks your system can reach, not just local ones.
    """
    routed_networks = {}
    try:
        # Detect if we're in WSL
        is_wsl = "microsoft" in platform.release().lower(
        ) or "WSL" in platform.uname().release

        if is_wsl:
            # Use Windows netstat from WSL
            cmd = ["/mnt/c/Windows/System32/netstat.exe", "-r"]
        else:
            cmd = ["netstat", "-r"]

        output = subprocess.check_output(cmd, text=True, errors="ignore")

        print(
            f"[get_windows_routed_networks] Parsing routing table for reachable networks..."
        )

        for line in output.splitlines():
            # Match routing table entries: destination netmask gateway interface
            match = re.match(
                r"^\s*(\d+\.\d+\.\d+\.\d+)\s+"
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"(\S+)\s+"
                r"(\d+\.\d+\.\d+\.\d+)", line.strip())

            if match:
                dest, netmask, gateway, interface = match.groups()
                try:
                    # Create network from destination and netmask
                    net = ipaddress.IPv4Network(f"{dest}/{netmask}",
                                                strict=False)

                    # Include all reachable networks (not just local private ones)
                    if (not net.is_loopback and not net.is_multicast
                            and not net.is_link_local and dest != "0.0.0.0"
                            and  # Skip default route
                            not str(net).endswith('.255/32')
                            and  # Skip broadcast addresses
                            str(net) != '255.255.255.255/32'
                            and  # Skip global broadcast
                            net.prefixlen >= 8  # Reasonable network size
                        ):
                        # Categorize the network type
                        network_type = "unknown"
                        if net.is_private:
                            network_type = "private"
                        elif gateway == "On-link":
                            network_type = "direct"
                        else:
                            network_type = "routed"

                        routed_networks[str(net)] = {
                            "gateway": gateway,
                            "interface": interface,
                            "method": "routing_table",
                            "type": network_type
                        }
                        if verbose:
                            print(
                                f"[get_windows_routed_networks] Found {network_type} network: {net} via {gateway}"
                            )

                except Exception as e:
                    if verbose:
                        print(
                            f"[get_windows_routed_networks] Error parsing {dest}/{netmask}: {e}"
                        )

    except Exception as e:
        if verbose:
            print(f"[get_windows_routed_networks] Error running netstat: {e}")

    if verbose:
        print(
            f"[get_windows_routed_networks] Found {len(routed_networks)} reachable networks"
        )
    return routed_networks


def get_network_interfaces() -> Dict[str, Dict[str, str]]:
    """
    Get network interfaces and their associated networks that we can reach.
    This helps discover networks beyond just the routing table.
    """
    interface_networks = {}

    try:
        # Detect if we're in WSL
        is_wsl = "microsoft" in platform.release().lower(
        ) or "WSL" in platform.uname().release

        if is_wsl:
            # Use Windows ipconfig from WSL
            cmd = ["/mnt/c/Windows/System32/ipconfig.exe", "/all"]
        else:
            cmd = ["ipconfig", "/all"]

        output = subprocess.check_output(cmd, text=True, errors="ignore")

        print(f"[get_network_interfaces] Parsing network interfaces...")

        current_interface = None
        current_ip = None

        for line in output.splitlines():
            line = line.strip()

            # Detect interface names
            if "adapter" in line.lower() and ":" in line:
                current_interface = line
                current_ip = None  # Reset IP for new interface
                continue

            # Look for IPv4 addresses
            if "IPv4 Address" in line or "IP Address" in line:
                # Extract IP address - handle both formats
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    print(
                        f"[get_network_interfaces] Found IP: {current_ip} on {current_interface}"
                    )

            # Look for subnet mask - this should come after the IP address
            if "Subnet Mask" in line and current_ip:
                mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if mask_match:
                    subnet_mask = mask_match.group(1)

                    try:
                        # Create network from IP and mask
                        network = ipaddress.IPv4Network(
                            f"{current_ip}/{subnet_mask}", strict=False)

                        if (not network.is_loopback
                                and not network.is_link_local
                                and network.prefixlen >= 8
                                and network.prefixlen
                                <= 30):  # Reasonable network sizes

                            interface_networks[str(network)] = {
                                "interface": current_interface or "Unknown",
                                "ip": current_ip,
                                "subnet_mask": subnet_mask,
                                "method": "interface_scan",
                                "type": "local_interface"
                            }
                            print(
                                f"[get_network_interfaces] ✓ Found LOCAL network: {network} (IP: {current_ip}) on {current_interface}"
                            )

                    except Exception as e:
                        print(
                            f"[get_network_interfaces] Error creating network from {current_ip}/{subnet_mask}: {e}"
                        )

                    # Reset for next interface
                    current_ip = None

    except Exception as e:
        print(f"[get_network_interfaces] Error running ipconfig: {e}")

    print(
        f"[get_network_interfaces] Found {len(interface_networks)} interface networks"
    )
    return interface_networks


def discover_adjacent_networks(known_networks: Dict[str, Dict]) -> Set[str]:
    """
    Discover adjacent networks that might be reachable from known networks.
    This expands the search to neighboring subnets.
    """
    adjacent_networks = set()

    print(f"[discover_adjacent_networks] Looking for adjacent networks...")

    for network_str, details in known_networks.items():
        try:
            network = ipaddress.IPv4Network(network_str, strict=False)

            # Only look at private networks to avoid scanning public internet
            if not network.is_private:
                continue

            # For /24 networks, check adjacent subnets
            if network.prefixlen == 24:
                base_ip = str(network.network_address)
                parts = base_ip.split('.')
                current_subnet = int(parts[2])

                # Check a few adjacent subnets
                for offset in [-2, -1, 1, 2]:
                    new_subnet = current_subnet + offset
                    if 0 <= new_subnet <= 255:
                        adjacent_net = f"{parts[0]}.{parts[1]}.{new_subnet}.0/24"
                        adjacent_networks.add(adjacent_net)
                        print(
                            f"[discover_adjacent_networks] Added adjacent network: {adjacent_net}"
                        )

            # For larger networks, check some common subdivisions
            elif network.prefixlen <= 20:
                # Add some common /24 subnets within larger networks
                base_ip = str(network.network_address)
                parts = base_ip.split('.')

                # Try some common subnet patterns
                for third_octet in [0, 1, 10, 100, 200]:
                    subnet_net = f"{parts[0]}.{parts[1]}.{third_octet}.0/24"
                    try:
                        test_net = ipaddress.IPv4Network(subnet_net)
                        if test_net.subnet_of(network):
                            adjacent_networks.add(subnet_net)
                            print(
                                f"[discover_adjacent_networks] Added subnet within {network}: {subnet_net}"
                            )
                    except:
                        pass

        except Exception as e:
            print(
                f"[discover_adjacent_networks] Error processing {network_str}: {e}"
            )

    print(
        f"[discover_adjacent_networks] Found {len(adjacent_networks)} adjacent networks"
    )
    return adjacent_networks


def get_arp_table_ips() -> Set[str]:
    """
    Returns a set of IP addresses found in the ARP table.
    Fixed to properly return IPs instead of just printing them.
    """
    ips = set()
    try:
        # Detect WSL
        is_wsl = "microsoft" in platform.release().lower(
        ) or "WSL" in platform.uname().release

        if platform.system() == "Windows" or is_wsl:
            # Use Windows arp.exe from WSL or Windows
            if is_wsl:
                arp_cmd = ["/mnt/c/Windows/System32/arp.exe", "-a"]
            else:
                arp_cmd = ["arp", "-a"]

            arp_output = subprocess.check_output(arp_cmd,
                                                 text=True,
                                                 errors="ignore")

            print(f"[get_arp_table_ips] Parsing Windows ARP table...")

            for line in arp_output.splitlines():
                # Windows ARP format: "  192.168.1.1          00-11-22-33-44-55     dynamic"
                parts = line.strip().split()
                if len(parts) >= 1 and "." in parts[0]:
                    ip = parts[0].strip()
                    try:
                        # Validate it's a proper IPv4 address
                        ip_addr = ipaddress.IPv4Address(ip)
                        # Only include private IPs, exclude broadcast and special addresses
                        if (ip_addr.is_private
                                and not str(ip_addr).endswith('.255')
                                and str(ip_addr) != '255.255.255.255'):
                            ips.add(ip)
                            print(f"[get_arp_table_ips] Found ARP entry: {ip}")
                    except Exception:
                        pass
        else:
            # Linux ip neigh command
            arp_output = subprocess.check_output(["ip", "neigh"],
                                                 text=True,
                                                 errors="ignore")

            print(f"[get_arp_table_ips] Parsing Linux neighbor table...")

            for line in arp_output.splitlines():
                parts = line.split()
                if len(parts) >= 1:
                    ip = parts[0]
                    try:
                        ip_addr = ipaddress.IPv4Address(ip)
                        if (ip_addr.is_private
                                and not str(ip_addr).endswith('.255')
                                and str(ip_addr) != '255.255.255.255'):
                            ips.add(ip)
                            print(
                                f"[get_arp_table_ips] Found neighbor entry: {ip}"
                            )
                    except Exception:
                        pass

    except Exception as e:
        print(f"[get_arp_table_ips] ARP table scan failed: {e}")

    print(f"[get_arp_table_ips] Found {len(ips)} unique IPs in ARP table")
    return ips


def get_common_networks() -> Set[str]:
    """
    Returns a set of common private IPv4 networks.
    These are typical default networks used in home/office environments.
    """
    common = {
        "192.168.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.1.0.0/24",
        "10.1.1.0/24",
        "172.16.0.0/24",
        "172.16.1.0/24",
    }
    print(f"[get_common_networks] Using {len(common)} common private networks")
    return common


def ping_ip(ip: str, timeout: int = 2) -> Tuple[str, bool, str]:
    """
    Ping a single IP address and return the result.
    Returns (ip, success, output/error)
    """
    try:
        # Use ping command appropriate for the platform
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

        result = subprocess.run(cmd,
                                capture_output=True,
                                text=True,
                                timeout=timeout + 1)

        if result.returncode == 0:
            return (ip, True, "Success")
        else:
            return (ip, False, "No response")

    except subprocess.TimeoutExpired:
        return (ip, False, "Timeout")
    except Exception as e:
        return (ip, False, f"Error: {e}")


async def ping_multiple_ips(ips: List[str],
                            max_workers: int = 20
                            ) -> Dict[str, Tuple[bool, str]]:
    """
    Ping multiple IPs concurrently and return results.
    """
    results = {}

    print(
        f"[ping_multiple_ips] Pinging {len(ips)} IPs with {max_workers} workers..."
    )

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers) as executor:
        # Submit all ping tasks
        future_to_ip = {executor.submit(ping_ip, ip): ip for ip in ips}

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_ip):
            ip, success, message = future.result()
            results[ip] = (success, message)

            if success:
                print(f"[ping_multiple_ips] ✓ {ip} - {message}")
            else:
                print(f"[ping_multiple_ips] ✗ {ip} - {message}")

    return results


def extract_ips_from_networks(networks: Set[str],
                              max_ips_per_network: int = 50) -> List[str]:
    """
    Extract individual IP addresses from network CIDR ranges.
    For large networks, scan a subset of IPs to avoid overwhelming the network.
    """
    all_ips = []

    for network_str in networks:
        try:
            network = ipaddress.IPv4Network(network_str, strict=False)

            # For /32 networks, just add the single IP
            if network.prefixlen == 32:
                all_ips.append(str(network.network_address))
                continue

            # For larger networks, just scan potential gateways (.1 and .254)
            if network.num_addresses > max_ips_per_network * 2:
                print(
                    f"[extract_ips_from_networks] Scanning gateway IPs (.1, .254) for large network {network}"
                )

                # Calculate .1 and .254 addresses for this network
                network_base = str(network.network_address)
                network_parts = network_base.split('.')

                # Try .1 address (common gateway)
                gateway_1 = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.1"
                if ipaddress.IPv4Address(gateway_1) in network:
                    all_ips.append(gateway_1)
                    print(
                        f"[extract_ips_from_networks] Added potential gateway: {gateway_1}"
                    )

                # Try .254 address (alternative gateway)
                gateway_254 = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.254"
                if ipaddress.IPv4Address(gateway_254) in network:
                    all_ips.append(gateway_254)
                    print(
                        f"[extract_ips_from_networks] Added potential gateway: {gateway_254}"
                    )

            else:
                # Small network, add all host IPs
                print(
                    f"[extract_ips_from_networks] Adding all {network.num_addresses-2} IPs from {network}"
                )
                for ip in network.hosts():
                    all_ips.append(str(ip))

        except Exception as e:
            print(
                f"[extract_ips_from_networks] Error processing network {network_str}: {e}"
            )

    return all_ips


async def discover_networks_for_bacnet(
        verbose: bool = False) -> Dict[str, List[str]]:
    """
    Discover networks that can be scanned for BACnet devices.

    Args:
        verbose: If True, print detailed discovery information

    Returns:
        Dict with 'responsive_networks' and 'responsive_ips' keys
    """
    if verbose:
        print("=== Network Discovery for BACnet Scanning ===\n")

    # Method 1: Get networks from Windows routing table (all reachable networks)
    if verbose:
        print(
            "1. Discovering reachable networks from Windows routing table...")
    routed_networks = get_windows_routed_networks(verbose)

    # Method 2: Get networks from network interfaces
    if verbose:
        print("\n2. Discovering networks from network interfaces...")
    interface_networks = get_network_interfaces()

    # Method 3: Get IPs from ARP table (active devices)
    if verbose:
        print("\n3. Discovering active IPs from ARP table...")
    arp_ips = get_arp_table_ips()

    # Method 4: Discover adjacent/neighboring networks
    if verbose:
        print("\n4. Discovering adjacent networks...")
    all_known_networks = {**routed_networks, **interface_networks}
    adjacent_networks_set = discover_adjacent_networks(all_known_networks)
    adjacent_networks = {
        net: {
            "method": "adjacent_discovery",
            "type": "adjacent"
        }
        for net in adjacent_networks_set
    }

    # Method 5: Add some common private networks as fallback
    if verbose:
        print("\n5. Adding common private networks as fallback...")
    common_networks_set = get_common_networks()
    common_networks = {
        net: {
            "method": "common_networks",
            "type": "common"
        }
        for net in common_networks_set
    }

    # Combine all discovered networks
    all_networks = {
        **routed_networks,
        **interface_networks,
        **adjacent_networks,
        **common_networks
    }

    if verbose:
        print(f"\nTotal unique networks found: {len(all_networks)}")

    # Extract IPs from networks for gateway scanning
    if verbose:
        print(f"\n6. Extracting gateway IPs from discovered networks...")
    network_ips = extract_ips_from_networks(set(all_networks.keys()),
                                            max_ips_per_network=50)

    # Combine ARP IPs with network IPs
    all_ips_to_ping = list(set(list(arp_ips) + network_ips))

    if verbose:
        print(f"\nPinging {len(all_ips_to_ping)} potential gateway IPs...")

    # Ping all discovered IPs
    ping_results = await ping_multiple_ips(all_ips_to_ping)

    # Get successful pings
    successful_pings = {
        ip: result
        for ip, result in ping_results.items() if result[0]
    }

    # Find responsive networks
    responsive_networks = set()
    responsive_ips = list(successful_pings.keys())

    for ip in successful_pings.keys():
        ip_addr = ipaddress.IPv4Address(ip)

        # Find all networks that contain this IP
        candidate_networks = []
        for net_str in all_networks.keys():
            try:
                network = ipaddress.IPv4Network(net_str, strict=False)
                if ip_addr in network and network.prefixlen <= 24:
                    candidate_networks.append(network)
            except:
                pass

        # Choose the most specific network (highest prefix length)
        if candidate_networks:
            most_specific = max(candidate_networks, key=lambda n: n.prefixlen)
            responsive_networks.add(str(most_specific))
            if verbose:
                print(
                    f"[discover_networks_for_bacnet] IP {ip} found in {len(candidate_networks)} networks, chose most specific: {most_specific}"
                )

    if verbose:
        print(f"\n=== DISCOVERY RESULTS ===")
        print(
            f"Responsive networks for BACnet scanning: {len(responsive_networks)}"
        )
        for net in sorted(responsive_networks):
            print(f"   - {net}")
        print(f"Responsive IPs found: {len(responsive_ips)}")
        for ip in sorted(responsive_ips,
                         key=lambda x: ipaddress.IPv4Address(x)):
            print(f"   - {ip}")

    return {
        'responsive_networks':
        sorted(list(responsive_networks)),
        'responsive_ips':
        sorted(responsive_ips, key=lambda x: ipaddress.IPv4Address(x))
    }


async def main():
    """
    Main function for standalone testing - shows verbose output.
    """
    results = await discover_networks_for_bacnet(verbose=True)
    print(f"\n=== FINAL RESULTS FOR BACNET SCANNING ===")
    print(f"Networks to scan: {results['responsive_networks']}")
    print(f"Responsive IPs: {results['responsive_ips']}")


if __name__ == "__main__":
    asyncio.run(main())
