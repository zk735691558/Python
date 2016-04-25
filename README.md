# Python
Something about python
PythonNetCode
chapter1

1_1_local_machine_info
import socket


def print_machine_info():
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    print "Host name: %s" %host_name
    print "IP address: %s" %ip_address

if __name__ == '__main__':
    print_machine_info()
    
1_2_remote_machine_info

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

import socket
from binascii import hexlify


def convert_ip4_address():
    for ip_addr in ['127.0.0.1', '192.168.0.1']:
        packed_ip_addr = socket.inet_aton(ip_addr)
        unpacked_ip_addr = socket.inet_ntoa(packed_ip_addr)
        print "IP Address: %s => Packed: %s, Unpacked: %s" %(ip_addr, hexlify(packed_ip_addr), unpacked_ip_addr)
    
if __name__ == '__main__':
    convert_ip4_address()
    
1_4_finding_service_name

import socket

def find_service_name():
    protocolname = 'tcp'
    for port in [80, 25]:
        print "Port: %s => service name: %s" %(port, socket.getservbyport(port, protocolname))
    
    print "Port: %s => service name: %s" %(53, socket.getservbyport(53, 'udp'))
    
if __name__ == '__main__':
    find_service_name()
    
    
1_5_integer_conversion

import socket

def convert_integer():
    data = 1234
    # 32-bit
    print "Original: %s => Long  host byte order: %s, Network byte order: %s" %(data, socket.ntohl(data), socket.htonl(data))
    # 16-bit
    print "Original: %s => Short  host byte order: %s, Network byte order: %s" %(data, socket.ntohs(data), socket.htons(data))

    
if __name__ == '__main__':
    convert_integer()
    
1_6_socket_timeout

import socket

def test_socket_timeout():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print "Default socket timeout: %s" %s.gettimeout()
    s.settimeout(100)
    print "Current socket timeout: %s" %s.gettimeout()    
    
if __name__ == '__main__':
    test_socket_timeout()


1_7_socket_errors

import sys
import socket
import argparse 


def main():
    # setup argument parsing
    parser = argparse.ArgumentParser(description='Socket Error Examples')
    parser.add_argument('--host', action="store", dest="host", required=False)
    parser.add_argument('--port', action="store", dest="port", type=int, required=False)
    parser.add_argument('--file', action="store", dest="file", required=False)
    given_args = parser.parse_args()
    host = given_args.host
    port = given_args.port
    filename = given_args.file
    
    # First try-except block -- create socket 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, e:
        print "Error creating socket: %s" % e
        sys.exit(1)
    
    # Second try-except block -- connect to given host/port
    try:
        s.connect((host, port))
    except socket.gaierror, e:
        print "Address-related error connecting to server: %s" % e
        sys.exit(1)
    except socket.error, e:
        print "Connection error: %s" % e
        sys.exit(1)
    
    # Third try-except block -- sending data
    try:
        s.sendall("GET %s HTTP/1.0\r\n\r\n" % filename)
    except socket.error, e:
        print "Error sending data: %s" % e
        sys.exit(1)
    
    while 1:
        # Fourth tr-except block -- waiting to receive data from remote host
        try:
            buf = s.recv(2048)
        except socket.error, e:
            print "Error receiving data: %s" % e
            sys.exit(1)
        if not len(buf):
            break
        # write the received data
        sys.stdout.write(buf) 
    
if __name__ == '__main__':
    main()
    
1_8_modify_buff_size

import socket

SEND_BUF_SIZE = 4096
RECV_BUF_SIZE = 4096

def modify_buff_size():
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    
    # Get the size of the socket's send buffer
    bufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    print "Buffer size [Before]:%d" %bufsize
    
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDBUF,
            SEND_BUF_SIZE)
    sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            RECV_BUF_SIZE)
    bufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    print "Buffer size [After]:%d" %bufsize

if __name__ == '__main__':
    modify_buff_size()
    
1_9_socket_modes

import socket

def test_socket_modes():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(1)
    s.settimeout(0.5)
    s.bind(("127.0.0.1", 0))
    
    socket_address = s.getsockname()
    print "Trivial Server lauched on socket: %s" %str(socket_address)
    while(1):
        s.listen(1)
  
if __name__ == '__main__':
    test_socket_modes()
    
1_10_reuse_socket_address

import socket
import sys


def reuse_socket_addr():
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )

    # Get the old state of the SO_REUSEADDR option
    old_state = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR )
    print "Old sock state: %s" %old_state

    # Enable the SO_REUSEADDR option
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
    new_state = sock.getsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR )
    print "New sock state: %s" %new_state

    local_port = 8282
    
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind( ('', local_port) )
    srv.listen(1)
    print ("Listening on port: %s " %local_port)
    while True:
        try:
            connection, addr = srv.accept()
            print 'Connected by %s:%s' % (addr[0], addr[1])
        except KeyboardInterrupt:
            break
        except socket.error, msg:
            print '%s' % (msg,)


if __name__ == '__main__':
    reuse_socket_addr()

1_11_print_machine_time

import ntplib
from time import ctime


def print_time():
    ntp_client = ntplib.NTPClient()
    response = ntp_client.request('pool.ntp.org')
    print ctime(response.tx_time)


if __name__ == '__main__':
    print_time()


1_12_sntp_client

import socket
import struct
import sys
import time

NTP_SERVER = "0.uk.pool.ntp.org"
TIME1970 = 2208988800L

def sntp_client():
    client = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    data = '\x1b' + 47 * '\0'
    client.sendto( data, ( NTP_SERVER, 123 ))
    data, address = client.recvfrom( 1024 )
    if data:
        print 'Response received from:', address
    t = struct.unpack( '!12I', data )[10]
    t -= TIME1970
    print '\tTime=%s' % time.ctime(t)


if __name__ == '__main__':
    sntp_client()


1_13a_echo_server

import socket
import sys
import argparse

host = 'localhost'
data_payload = 2048
backlog = 5 


def echo_server(port):
    """ A simple echo server """
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable reuse address/port 
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the port
    server_address = (host, port)
    print "Starting up echo server  on %s port %s" % server_address
    sock.bind(server_address)
    # Listen to clients, backlog argument specifies the max no. of queued connections
    sock.listen(backlog) 
    while True: 
        print "Waiting to receive message from client"
        client, address = sock.accept() 
        data = client.recv(data_payload) 
        if data:
            print "Data: %s" %data
            client.send(data)
            print "sent %s bytes back to %s" % (data, address)
        # end connection
        client.close() 
   
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args() 
    port = given_args.port
    echo_server(port)
    
1_13b_echo_client

import socket
import sys

import argparse

host = 'localhost'

def echo_client(port):
    """ A simple echo client """
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the server
    server_address = (host, port)
    print "Connecting to %s port %s" % server_address
    sock.connect(server_address)
    
    # Send data
    try:
        # Send data
        message = "Test message. This will be echoed"
        print "Sending %s" % message
        sock.sendall(message)
        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print "Received: %s" % data
    except socket.errno, e:
        print "Socket error: %s" %str(e)
    except Exception, e:
        print "Other exception: %s" %str(e)
    finally:
        print "Closing connection to the server"
        sock.close()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args() 
    port = given_args.port
    echo_client(port)
