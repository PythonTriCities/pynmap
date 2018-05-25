#!/usr/bin/env python

import nmap

scan_range = '172.16.1.1/24'
scan_ports = '22,53,80,443'

nm = nmap.PortScanner()

nm.scan(scan_range, scan_ports)

for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

for proto in nm[host].all_protocols():
    print('----------')
    print('Protocol : %s' % proto)

lport = nm[host][proto].keys()
#lport.sort()
for port in lport:
    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

print('----------------------------------------------------')
# print result as CSV
print(nm.csv())


print('----------------------------------------------------')
# If you want to do a pingsweep on network 192.168.1.0/24:
nm.scan(hosts=scan_range, arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{0}:{1}'.format(host, status))


print('----------------------------------------------------')
# Asynchronous usage of PortScannerAsync
nma = nmap.PortScannerAsync()


def callback_result(host, scan_result):
    print('------------------')
    print(host, scan_result)
    nma.scan(hosts='192.168.1.0/30', arguments='-sP', callback=callback_result)
    while nma.still_scanning():
        print('Waiting ...')
        nma.wait(2)
