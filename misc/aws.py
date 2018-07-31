#!/usr/bin/env python

import simplejson as json
import netaddr
import urllib2

content = urllib2.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json').read()

data = json.loads(content)['prefixes']

cloudfront = []
ec2 = []
amazon = []

for key in data:
    if key['service'] == 'CLOUDFRONT' and key['region'] != 'cn-north-1':
        cloudfront.append(netaddr.IPNetwork(key['ip_prefix']))
    if key['service'] == 'EC2' and key['region'] != 'cn-north-1':
        ec2.append(netaddr.IPNetwork(key['ip_prefix']))
    if key['service'] == 'AMAZON' and key['region'] != 'cn-north-1':
        amazon.append(netaddr.IPNetwork(key['ip_prefix']))
    amazon = [block for block in amazon if block not in ec2 and block not in cloudfront]

print "==================== AMAZON ========================"
for net in netaddr.cidr_merge(amazon):
    print net

print "==================== EC2 ========================"
for net in netaddr.cidr_merge(ec2):
    print net

print "==================== CLOUDFRONT ========================"
for net in netaddr.cidr_merge(cloudfront):
    print net

print "==================== TOTAL ========================"
for net in netaddr.cidr_merge(cloudfront + ec2 + amazon):
    print net