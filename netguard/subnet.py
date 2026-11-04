"""IPv4 addressing and subnetting (OSI Layer 3 fundamentals)."""

import ipaddress
import math


def _binary(addr):
    return ".".join(f"{octet:08b}" for octet in addr.packed)


def _class_of(addr):
    first = addr.packed[0]
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved)"


def describe(cidr):
    """Return a dict describing a network given in CIDR notation."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("only IPv4 is supported")

    if net.prefixlen >= 31:
        hosts = list(net.hosts()) or [net.network_address]
        usable = len(hosts) if net.prefixlen == 31 else 1
        first, last = hosts[0], hosts[-1]
    else:
        usable = net.num_addresses - 2
        first = net.network_address + 1
        last = net.broadcast_address - 1

    return {
        "cidr": str(net),
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "prefix": net.prefixlen,
        "first_host": str(first),
        "last_host": str(last),
        "total_addresses": net.num_addresses,
        "usable_hosts": usable,
        "class": _class_of(net.network_address),
        "private": net.is_private,
        "netmask_binary": _binary(net.netmask),
        "network_binary": _binary(net.network_address),
    }


def split(cidr, new_prefix):
    """Split a network into equal subnets of /new_prefix."""
    net = ipaddress.ip_network(cidr, strict=False)
    if new_prefix <= net.prefixlen or new_prefix > 32:
        raise ValueError("new prefix must be longer than the original and <= 32")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


def vlsm(base_cidr, host_counts):
    """Variable Length Subnet Masking.

    Allocate one subnet per requirement (number of hosts), largest first,
    packing them from the start of base_cidr without overlap.
    Returns a list of dicts ordered as the allocation was made.
    """
    base = ipaddress.ip_network(base_cidr, strict=False)
    cursor = int(base.network_address)
    end = int(base.broadcast_address)
    plan = []
    for need in sorted(host_counts, reverse=True):
        if need < 1:
            raise ValueError("host requirement must be >= 1")
        bits = max(2, math.ceil(math.log2(need + 2)))  # +2: network & broadcast
        size = 2 ** bits
        if cursor % size:                              # align to block boundary
            cursor += size - (cursor % size)
        if cursor + size - 1 > end:
            raise ValueError(f"{base} is too small for the requested hosts")
        subnet = ipaddress.ip_network((cursor, 32 - bits))
        plan.append({
            "requested_hosts": need,
            "subnet": str(subnet),
            "usable_hosts": size - 2,
            "netmask": str(subnet.netmask),
            "first_host": str(subnet.network_address + 1),
            "last_host": str(subnet.broadcast_address - 1),
            "broadcast": str(subnet.broadcast_address),
        })
        cursor += size
    return plan


def same_subnet(ip_a, ip_b, mask_or_prefix):
    """Would two hosts talk directly (same L2 segment) or via the gateway?"""
    net_a = ipaddress.ip_network(f"{ip_a}/{mask_or_prefix}", strict=False)
    return ipaddress.ip_address(ip_b) in net_a
