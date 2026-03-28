#!/usr/bin/env python3

"""generate iplist from bgp isn and aws json."""

import json
import re
import sys
from collections import defaultdict
from typing import List, Optional
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


def normalize_ip(ip_str: str) -> str:
    """Normalize IP address by removing leading zeros from octets.

    netaddr rejects IPs like '192.168.001.001' but accepts '192.168.1.1'.
    This function normalizes such IPs before creating IPNetwork objects.

    Args:
        ip_str: IP address string (e.g., '204.154.094.000/23')

    Returns:
        Normalized IP string (e.g., '204.154.94.0/23')
    """
    # Handle CIDR notation
    if "/" in ip_str:
        ip_part, prefix = ip_str.rsplit("/", 1)
    else:
        ip_part = ip_str
        prefix = None

    # For IPv4, remove leading zeros from each octet
    if "." in ip_part and ":" not in ip_part:
        octets = ip_part.split(".")
        normalized_octets = [str(int(octet)) for octet in octets]
        ip_part = ".".join(normalized_octets)

    if prefix:
        return f"{ip_part}/{prefix}"
    return ip_part


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
            network = netaddr.IPNetwork(normalize_ip(str(network)))

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


def fetch_china_ip_list(ipv6: bool = True) -> netaddr.IPSet:
    """Fetch China IP ranges from mayaxcn/china-ip-list.

    Args:
        ipv6: Whether to include IPv6 ranges. Defaults to True.

    Returns:
        IPSet containing all China IP ranges for efficient lookup.
    """
    urls = [
        "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt"
    ]
    if ipv6:
        urls.append(
            "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute_v6.txt"
        )

    china_ips: List[netaddr.IPNetwork] = []
    invalid_count = 0

    for url in urls:
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            print(
                f"Warning: Failed to fetch China IP list from {url}: {e}",
                file=sys.stderr,
            )
            continue

        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                network = netaddr.IPNetwork(line)
                china_ips.append(network)
            except netaddr.AddrFormatError:
                invalid_count += 1
                continue

    if invalid_count > 0:
        print(
            f"Warning: Skipped {invalid_count} invalid lines from China IP list",
            file=sys.stderr,
        )

    return netaddr.IPSet(china_ips)


def parse_and_filter_blocks(text: str, china_set: netaddr.IPSet) -> List[str]:
    """Parse output and filter China IPs at sub-block level.

    Structure:
    - Major sections are separated by lines of "###...###"
    - Within sections, sub-blocks start with "### SERVICE ###"
    - Comments start with "#"
    - Each sub-block is filtered and merged independently

    Returns list of output lines preserving structure.
    """
    result = []
    current_section_header = ""
    current_subblock_header = ""
    current_content = []

    def flush_subblock():
        nonlocal current_subblock_header, current_content
        if current_content or current_subblock_header:
            # Output sub-block header if exists
            if current_subblock_header:
                result.append(current_subblock_header)
            # Filter and merge content
            if current_content:
                filtered = filter_and_merge_content(current_content, china_set)
                result.extend(filtered)
            current_subblock_header = ""
            current_content = []

    def flush_section_header():
        nonlocal current_section_header
        if current_section_header:
            result.append(current_section_header)
            current_section_header = ""

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        # Major section separator (all #, no other content)
        if all(c == "#" for c in stripped):
            flush_subblock()
            flush_section_header()
            result.append(line)
        # Sub-block header like "### AMAZON ###"
        elif stripped.startswith("###") and stripped.endswith("###"):
            flush_subblock()
            current_subblock_header = line
        # Comment lines
        elif stripped.startswith("#"):
            flush_subblock()
            flush_section_header()
            result.append(line)
        else:
            current_content.append(line)

    # Flush final subblock
    flush_subblock()

    return result


def filter_and_merge_content(
    content_lines: List[str], china_set: netaddr.IPSet
) -> List[str]:
    """Filter China IPs from content lines and merge remaining CIDRs."""
    networks: List[netaddr.IPNetwork] = []

    for line in content_lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            network = netaddr.IPNetwork(stripped)
            networks.append(network)
        except (netaddr.AddrFormatError, ValueError):
            continue

    if not networks:
        return content_lines

    # Create IPSet from networks and subtract China IPs
    block_set = netaddr.IPSet(networks)
    result_set = block_set - china_set

    if not result_set:
        return []

    # Convert back to CIDRs and return as strings
    merged = netaddr.cidr_merge(list(result_set.iter_cidrs()))
    return [str(network) for network in merged]


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
            try:
                network = netaddr.IPNetwork(normalize_ip(match.group(0)))
                if is_valid_public_ip(network):
                    total.append(network)
                else:
                    invalid_count += 1
            except netaddr.AddrFormatError:
                invalid_count += 1
        if ipv6:
            match = cidr6_regex.search(line)
            if match:
                try:
                    network = netaddr.IPNetwork(normalize_ip(match.group(0)))
                    if is_valid_public_ip(network):
                        total.append(network)
                    else:
                        invalid_count += 1
                except netaddr.AddrFormatError:
                    invalid_count += 1

    if invalid_count > 0:
        print(
            f"Filtered {invalid_count} invalid/bogon IP ranges from AS{asnumber}",
            file=sys.stderr,
        )

    total = netaddr.cidr_merge(total)
    return "\n".join([str(network).strip() for network in total])


if __name__ == "__main__":
    try:
        template = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath="./")
        ).get_template("gfwiplist.j2")
        template.globals["as2cidr"] = as2cidr
        template.globals["aws2cidr"] = aws2cidr
        template.globals["cf2cidr"] = cf2cidr
        template.globals["gh2cidr"] = gh2cidr

        print("Fetching China IP list...", file=sys.stderr)
        china_set = fetch_china_ip_list()
        print(f"Loaded China IP ranges (IPSet size: {china_set.size})", file=sys.stderr)

        print("Rendering template...", file=sys.stderr)
        output = template.render()

        print("Processing blocks...", file=sys.stderr)
        result_lines = parse_and_filter_blocks(output, china_set)

        print("\n".join(result_lines))

    except Exception as e:
        import traceback

        print(f"Error generating IP list: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
