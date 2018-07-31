#!/use/bin/env python

import re
import sys
import urllib2

import jinja2
import netaddr
import simplejson

import whois


def as2cidr(asnumber):

    nic_client = whois.NICClient()
    whois_result = nic_client.whois_lookup(options={'whoishost': 'whois.radb.net'},
                                     query_arg="-i origin AS" + str(asnumber),
                                     flags=0)

    cidr_regex = re.compile(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[1-2]?[0-9])\b')

    addr = []
    for line in whois_result.splitlines():
        match = cidr_regex.search(line)
        if match:
            addr.append(netaddr.IPNetwork(match.group(0)))

    cidr_result = ""
    for network in netaddr.cidr_merge(addr):
        cidr_result = cidr_result + '\n' + str(network)

    # strip empty lines
    cidr_result = '\n'.join([line.strip() for line in cidr_result.splitlines() if line.strip()])

    return cidr_result

def aws2cidr(type):
    content = urllib2.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json').read()
    data = simplejson.loads(content)['prefixes']

    amazon_blocks = {}
    for key in data:
        if not  key['region'].startswith('cn-'):
            if not key['service'] in amazon_blocks:
                amazon_blocks[key['service']] = []
            amazon_blocks[key['service']].append(netaddr.IPNetwork(key['ip_prefix']))

    # 'AMAZON' block contains other blocks. exclude them
    temp_amazon = []
    for block in amazon_blocks['AMAZON']:
        for key in amazon_blocks:
            if key != 'AMAZON':
                if block not in amazon_blocks[key]:
                    temp_amazon.append(block)
    amazon_blocks['AMAZON'] = temp_amazon

    total = []
    for key in amazon_blocks:
        total = total + amazon_blocks[key]


    cidr_result = ""

    if type == "all":
        # all of the merged blocks
        for network in netaddr.cidr_merge(total):
            cidr_result = cidr_result + '\n' + str(network)
    elif type == "split":
        # blocks that split
        for key in amazon_blocks:
            cidr_result = cidr_result + '\n# Amazon ' + key
            for network in netaddr.cidr_merge(amazon_blocks[key]):
                cidr_result = cidr_result + '\n' + str(network)
    else:
        # blocks of a certain type
        for network in netaddr.cidr_merge(amazon_blocks[type]):
            cidr_result = cidr_result + '\n' + str(network)

    # strip empty lines
    cidr_result = '\n'.join([line.strip() for line in cidr_result.splitlines() if line.strip()])

    return cidr_result




template = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="./")).get_template('gfwiplist.j2')
template.globals['as2cidr'] = as2cidr
template.globals['aws2cidr'] = aws2cidr
output = template.render()

print output
