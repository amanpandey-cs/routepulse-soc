import ipaddress
from typing import Dict, Any, List

def calculate_subnet(ip_str: str, prefix: int) -> Dict[str, Any]:
    """
    Computes comprehensive subnet metrics matching NetCalc Pro specifications.
    """
    # Clean and validate IP
    ip_str = ip_str.strip()
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
    except Exception as e:
        raise ValueError(f"Invalid IPv4 Address: {e}")

    if prefix < 0 or prefix > 32:
        raise ValueError("CIDR prefix must be between 0 and 32")

    network_interface = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
    network = network_interface.network

    netmask = str(network.netmask)
    hostmask = str(network.hostmask)
    network_address = str(network.network_address)
    broadcast_address = str(network.broadcast_address)
    
    total_hosts = network.num_addresses
    if prefix == 32:
        usable_hosts = 1
        first_usable = str(network.network_address)
        last_usable = str(network.network_address)
    elif prefix == 31:
        usable_hosts = 2
        first_usable = str(network.network_address)
        last_usable = str(network.broadcast_address)
    else:
        usable_hosts = max(0, total_hosts - 2)
        first_usable = str(network.network_address + 1)
        last_usable = str(network.broadcast_address - 1)

    # IP Class Determination
    first_octet = int(ip_str.split(".")[0])
    if 1 <= first_octet <= 126:
        ip_class = "A"
    elif 128 <= first_octet <= 191:
        ip_class = "B"
    elif 192 <= first_octet <= 223:
        ip_class = "C"
    elif 224 <= first_octet <= 239:
        ip_class = "D (Multicast)"
    elif 240 <= first_octet <= 255:
        ip_class = "E (Experimental)"
    elif first_octet == 127:
        ip_class = "Loopback"
    else:
        ip_class = "Unknown"

    # Binary representations
    def to_binary_dotted(ip_addr_int: int) -> str:
        b_str = f"{ip_addr_int:032b}"
        return f"{b_str[0:8]}.{b_str[8:16]}.{b_str[16:24]}.{b_str[24:32]}"

    bin_netmask = to_binary_dotted(int(network.netmask))
    bin_network = to_binary_dotted(int(network.network_address))
    bin_ip = to_binary_dotted(int(ip_obj))

    # IP Scope
    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_multicast = ip_obj.is_multicast
    is_reserved = ip_obj.is_reserved
    is_global = ip_obj.is_global

    scope = "Public (Internet Routable)"
    if is_private:
        scope = "Private (RFC 1918)"
    elif is_loopback:
        scope = "Loopback (RFC 1122)"
    elif is_multicast:
        scope = "Multicast (RFC 5771)"
    elif is_reserved:
        scope = "Reserved / Carrier Grade NAT"

    return {
        "ip": ip_str,
        "cidr_prefix": prefix,
        "cidr_notation": f"{network_address}/{prefix}",
        "subnet_mask": netmask,
        "wildcard_mask": hostmask,
        "network_address": network_address,
        "broadcast_address": broadcast_address,
        "first_usable_ip": first_usable,
        "last_usable_ip": last_usable,
        "total_hosts": total_hosts,
        "usable_hosts": usable_hosts,
        "ip_class": ip_class,
        "binary_subnet_mask": bin_netmask,
        "binary_network_address": bin_network,
        "binary_ip": bin_ip,
        "scope": scope,
        "is_private": is_private,
        "hex_ip": hex(int(ip_obj))
    }

def check_ip_in_subnet(candidate_ip: str, network_cidr: str) -> Dict[str, Any]:
    """
    Checks if a candidate IP belongs to a specified CIDR range, and calculates offset.
    """
    try:
        ip = ipaddress.ip_address(candidate_ip.strip())
        net = ipaddress.ip_network(network_cidr.strip(), strict=False)
        is_member = ip in net
        
        offset = None
        if is_member and ip.version == 4 and net.version == 4:
            offset = int(ip) - int(net.network_address)
            
        return {
            "candidate_ip": str(ip),
            "network_cidr": str(net),
            "is_member": is_member,
            "host_index": offset,
            "total_hosts": net.num_addresses,
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address) if net.version == 4 else None,
            "version": f"IPv{ip.version}"
        }
    except Exception as e:
        raise ValueError(f"Subnet membership evaluation error: {e}")

