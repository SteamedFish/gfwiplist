#!/usr/bin/env python3

"""generate iplist from bgp isn and aws json."""

import json
import re
from collections import defaultdict
from typing import List
from urllib.request import urlopen

import jinja2
import netaddr
import whois
import requests


def aws2cidr(split: bool = True, ipv6: bool = True) -> str:
    """read aws cidrs.
    split: amazon put cidrs in different services. Don't merge those services
    ipv6: enable ipv6
    """

    content = urlopen(
        "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10
    ).read()

    ipv4data = json.loads(content)["prefixes"]
    ipv6data = json.loads(content)["ipv6_prefixes"]

    resultdict = defaultdict(list)

    for key in ipv4data:
        if not key["region"].startswith("cn-"):
            resultdict[key["service"]].append(netaddr.IPNetwork(key["ip_prefix"]))
    if ipv6:
        for key in ipv6data:
            if not key["region"].startswith("cn-"):
                resultdict[key["service"]].append(netaddr.IPNetwork(key["ipv6_prefix"]))

    if not split:
        # merge all cidr blocks
        total: List[netaddr.IPNetwork] = []
        for key in resultdict:
            total += resultdict[key]
        total = netaddr.cidr_merge(total)
        return "\n".join([str(network).strip() for network in total])

    # 'Amazon' service is a special service that may contain other services.
    # Exclude other services.
    amazon: List[netaddr.IPNetwork] = []
    for block in resultdict["AMAZON"]:
        for key in resultdict:
            if key != "AMAZON" and block not in resultdict[key]:
                amazon.append(block)
    resultdict["AMAZON"] = amazon

    result = ""
    for key in resultdict:
        if len(result) == 0:
            result = f"### {key} ###"
        else:
            result = f"{result}\n### {key} ###"
        resultdict[key] = netaddr.cidr_merge(resultdict[key])
        string = "\n".join([str(network).strip() for network in resultdict[key]])
        result = f"{result}\n{string}"

    return result


def cf2cidr(ipv6: bool = True) -> str:
    """Fetch Cloudflare IP ranges.

    Args:
        ipv6: Whether to include IPv6 ranges. Defaults to True.

    Returns:
        String containing Cloudflare CIDR blocks, one per line.
    """
    result = ""
    result += requests.get("https://www.cloudflare.com/ips-v4").text
    if ipv6:
        result += requests.get("https://www.cloudflare.com/ips-v6").text
    return result


def gh2cidr(ipv6: bool = True) -> str:
    """Fetch GitHub IP ranges from GitHub API.

    Args:
        ipv6: Whether to include IPv6 ranges. Defaults to True.

    Returns:
        String containing GitHub CIDR blocks, one per line.

    Note:
        GitHub is currently using a lot of Microsoft's IP.
        Cannot determine by AS number.
    """
    ghmeta = requests.get("https://api.github.com/meta").json()
    github: List[netaddr.IPNetwork] = []
    invalid_count = 0
    for block in (
        "hooks",
        "web",
        "api",
        "git",
        "github_enterprise_importer",
        "packages",
        "pages",
        "importer",
        # "actions",
        # "actions_macos",
        "codespaces",
        "copilot",
    ):
        ipranges = ghmeta[block]
        for ip in ipranges:
            if not ipv6:
                if ":" in ip:
                    continue
            try:
                network = netaddr.IPNetwork(ip)
                if is_valid_public_ip(network):
                    github.append(network)
                else:
                    invalid_count += 1
            except netaddr.AddrFormatError:
                invalid_count += 1
                continue

    if invalid_count > 0:
        print(
            f"Filtered {invalid_count} invalid/bogon IP ranges from GitHub",
            file=sys.stderr,
        )

    return "\n".join([str(network).strip() for network in netaddr.cidr_merge(github)])


def is_valid_public_ip(network: netaddr.IPNetwork) -> bool:
    """Check if IP network is valid and publicly routable.

    Excludes:
    - Private/reserved ranges (RFC 1918, loopback, multicast, etc.)
    - Link-local addresses
    - Documentation/testing ranges
    """
    # IPv4 bogon ranges
    bogon_ranges_v4 = [
        netaddr.IPNetwork("0.0.0.0/8"),  # Current network
        netaddr.IPNetwork("10.0.0.0/8"),  # Private
        netaddr.IPNetwork("127.0.0.0/8"),  # Loopback
        netaddr.IPNetwork("169.254.0.0/16"),  # Link-local
        netaddr.IPNetwork("172.16.0.0/12"),  # Private
        netaddr.IPNetwork("192.0.2.0/24"),  # TEST-NET-1
        netaddr.IPNetwork("192.88.99.0/24"),  # 6to4 Relay Anycast
        netaddr.IPNetwork("192.168.0.0/16"),  # Private
        netaddr.IPNetwork("198.18.0.0/15"),  # Benchmark testing
        netaddr.IPNetwork("198.51.100.0/24"),  # TEST-NET-2
        netaddr.IPNetwork("203.0.113.0/24"),  # TEST-NET-3
        netaddr.IPNetwork("224.0.0.0/4"),  # Multicast
        netaddr.IPNetwork("240.0.0.0/4"),  # Reserved
        netaddr.IPNetwork("255.255.255.255/32"),  # Broadcast
    ]

    # IPv6 bogon ranges
    bogon_ranges_v6 = [
        netaddr.IPNetwork("::/128"),  # Unspecified
        netaddr.IPNetwork("::1/128"),  # Loopback
        netaddr.IPNetwork("::ffff:0:0/96"),  # IPv4-mapped
        netaddr.IPNetwork("64:ff9b::/96"),  # IPv4-IPv6 translation
        netaddr.IPNetwork("100::/64"),  # Discard prefix
        netaddr.IPNetwork("2001::/32"),  # Teredo
        netaddr.IPNetwork("2001:10::/28"),  # ORCHID
        netaddr.IPNetwork("2001:db8::/32"),  # Documentation
        netaddr.IPNetwork("fc00::/7"),  # Unique local
        netaddr.IPNetwork("fe80::/10"),  # Link-local
        netaddr.IPNetwork("ff00::/8"),  # Multicast
    ]

    try:
        # Check if it's a valid IP network
        if not isinstance(network, netaddr.IPNetwork):
            network = netaddr.IPNetwork(str(network))

        # Skip if private
        if network.is_private():
            return False

        # Skip if reserved
        if network.is_reserved():
            return False

        # Skip if multicast
        if network.is_multicast():
            return False

        # Skip if loopback
        if network.is_loopback():
            return False

        # Skip if link-local
        if network.is_link_local():
            return False

        # Check against bogon lists
        if network.version == 4:
            for bogon in bogon_ranges_v4:
                if network in bogon or network == bogon:
                    return False
        elif network.version == 6:
            for bogon in bogon_ranges_v6:
                if network in bogon or network == bogon:
                    return False

        return True
    except (netaddr.AddrFormatError, ValueError):
        return False


def as2cidr(asnumber: int, ipv6: bool = True) -> str:
    """Return networks from a asn."""

    nic_client = whois.NICClient()
    whois_result = nic_client.whois_lookup(
        options={"whoishost": "whois.radb.net"},
        query_arg=f"-i origin AS{asnumber}",
        flags=0,
    )

    cidr_regex = re.compile(
        (
            r"\b"
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            r"/(3[0-2]|[1-2]?[0-9])"
            r"\b"
        )
    )

    cidr6_regex = re.compile(
        (
            r"\b"
            r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
            r"([0-9a-fA-F]{1,4}:){1,7}:|"
            r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
            r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
            r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
            r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
            r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
            r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
            r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
            r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
            r"::(ffff(:0{1,4}){0,1}:){0,1}"
            r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
            r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
            r"([0-9a-fA-F]{1,4}:){1,4}:"
            r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
            r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
            r"\/(1[01][0-9]|12[0-8]|[0-9]{1,2})"
            r"\b"
        )
    )

    total: List[netaddr.IPNetwork] = []
    invalid_count = 0
    for line in whois_result.splitlines():
        match = cidr_regex.search(line)
        if match:
            network = netaddr.IPNetwork(match.group(0))
            if is_valid_public_ip(network):
                total.append(network)
            else:
                invalid_count += 1
        if ipv6:
            match = cidr6_regex.search(line)
            if match:
                network = netaddr.IPNetwork(match.group(0))
                if is_valid_public_ip(network):
                    total.append(network)
                else:
                    invalid_count += 1

    if invalid_count > 0:
        print(
            f"Filtered {invalid_count} invalid/bogon IP ranges from AS{asnumber}",
            file=sys.stderr,
        )

    total = netaddr.cidr_merge(total)
    return "\n".join([str(network).strip() for network in total])


if __name__ == "__main__":
    import sys

    try:
        template = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath="./")
        ).get_template("gfwiplist.j2")
        template.globals["as2cidr"] = as2cidr
        template.globals["aws2cidr"] = aws2cidr
        template.globals["cf2cidr"] = cf2cidr
        template.globals["gh2cidr"] = gh2cidr
        output = template.render()
        print(output)
    except Exception as e:
        print(f"Error generating IP list: {e}", file=sys.stderr)
        sys.exit(1)
