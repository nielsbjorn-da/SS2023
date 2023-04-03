#!/usr/bin/env python3
import fcntl
import ssl
import struct
import os
import time
from scapy.all import *


# Create tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'sen%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))
print("Setting up interface")
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
print("Done")

# Routing
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))


# Create TCP socket
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = socket.socket(socket.AF_INET)
SERVER_IP, SERVER_PORT = '10.9.0.11', 9090
# Set context
certFile = './certs/server.crt'
keyFile = './certs/server.key'
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

#context.verify_mode = ssl.CERT_OPTIONAL
context.check_hostname = False #should be set to true and cert should get accepted
context.load_verify_locations(cafile=certFile)
context.load_cert_chain(certfile=certFile, keyfile=keyFile)
#context = ssl.create_default_context()



# wrap the socket in a TLS/SSL layer
secure_sock = context.wrap_socket(sock, server_hostname=SERVER_IP)
secure_sock.connect((SERVER_IP, SERVER_PORT))

# Send a message
message = 'Hello, server!'
#time.sleep(5)
# create an IP packet
ip = IP(src="192.168.53.99", dst="192.168.60.5")

# create an ICMP ping packet
icmp = ICMP(type=8, code=0)

# create TCP packet
tcp = TCP(sport=1234, dport=80, flags="S", seq=1)

# create a payload for the ICMP packet
data = message.encode()

# combine the IP and ICMP packets
packet = ip/icmp/data
tcp_packet = ip/tcp

secure_sock.sendall(bytes(packet))

while True:
# this will block until at least one interface is ready
	ready, _, _ = select.select([secure_sock, tun], [], [])

	for fd in ready:
		print(fd)
		print(secure_sock)
		print(tun)
		if fd is secure_sock:
			print("waiting ss")
			#data, (ip, port) = secure_sock.recv(2048)
			data = secure_sock.recv(2048)
			print("received:", data)
			pkt = IP(data)
			print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
			print(pkt)
			break
			os.write(tun, bytes(pkt))

		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
			secure_sock.sendto(packet, (SERVER_IP, SERVER_PORT))
