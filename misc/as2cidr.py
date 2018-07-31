#!/usr/bin/env python

import re
import sys

import netaddr

import whois

asnumber = int(sys.argv[1])

nic_client = whois.NICClient()
result = nic_client.whois_lookup(options={'whoishost': 'whois.radb.net'},
                              query_arg="-i origin AS" + str(asnumber),
                              flags=0)

cidr_regex = re.compile(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[1-2]?[0-9])\b')
addr = []

for line in result.splitlines():
    match = cidr_regex.search(line)
    if match:
        addr.append(netaddr.IPNetwork(match.group(0)))

for net in netaddr.cidr_merge(addr):
    print net
