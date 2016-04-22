# Python
Something about python
PythonNetCode
chapter1

1_1_local_machine_info
#!/usr/bin/env python
# Python Network Programming Cookbook -- Chapter - 1
# This program is optimized for Python 2.7.
# It may run on any other version with/without modifications.

import socket


def print_machine_info():
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    print "Host name: %s" %host_name
    print "IP address: %s" %ip_address

if __name__ == '__main__':
    print_machine_info()
    
1_2_remote_machine_info
#!/usr/bin/env python
# Python Network Programming Cookbook -- Chapter - 1
# This program is optimized for Python 2.7.
# It may run on any other version with/without modifications.


import socket

def get_remote_machine_info():
    remote_host = 'www.python.org'
    try:
        print "IP address of %s: %s" %(remote_host, socket.gethostbyname(remote_host))
    except socket.error, err_msg:
        print "%s: %s" %(remote_host, err_msg)
    
if __name__ == '__main__':
    get_remote_machine_info()

1_3_ip4_address_conversion
#!/usr/bin/env python
# Python Network Programming Cookbook -- Chapter - 1
# This program requires Python 2.7 or any later version

import socket
from binascii import hexlify


def convert_ip4_address():
    for ip_addr in ['127.0.0.1', '192.168.0.1']:
        packed_ip_addr = socket.inet_aton(ip_addr)
        unpacked_ip_addr = socket.inet_ntoa(packed_ip_addr)
        print "IP Address: %s => Packed: %s, Unpacked: %s" %(ip_addr, hexlify(packed_ip_addr), unpacked_ip_addr)
    
if __name__ == '__main__':
    convert_ip4_address()
