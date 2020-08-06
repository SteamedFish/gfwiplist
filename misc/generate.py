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


def aws2cidr(split: bool = True) -> str:
    """read aws cidrs.
    split: amazon put cidrs in different services. Don't merge those services
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
    for key in ipv6data:
        if not key["region"].startswith("cn-"):
            resultdict[key["service"]].append(netaddr.IPNetwork(key["ipv6_prefix"]))

    if not split:
        # merge all cidr blocks
        total: List(netaddr.IPNetwork) = []
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


def as2cidr(asnumber: int) -> str:
    """Return networks from a asn."""

    nic_client = whois.NICClient()
    whois_result = nic_client.whois_lookup(
        options={"whoishost": "whois.radb.net"},
        query_arg=f"-i origin AS{asnumber}",
        flags=0,
    )

    cidr_regex = re.compile(
        (
            r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[1-2]?[0-9])\b"
        )
    )

    total: List(netaddr.IPNetwork) = []
    for line in whois_result.splitlines():
        match = cidr_regex.search(line)
        if match:
            total.append(netaddr.IPNetwork(match.group(0)))

    total = netaddr.cidr_merge(total)
    return "\n".join([str(network).strip() for network in total])


if __name__ == "__main__":
    template = jinja2.Environment(
        loader=jinja2.FileSystemLoader(searchpath="./")
    ).get_template("gfwiplist.j2")
    template.globals["as2cidr"] = as2cidr
    template.globals["aws2cidr"] = aws2cidr
    output = template.render()
    print(output)
