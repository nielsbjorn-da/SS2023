#!/usr/bin/env python3
import ssl

from scapy.all import *
import fcntl
import struct
import os
import time

from scapy.layers.inet import IP

# TUN interface
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

# Configure the tun interface
os.system("ip addr add 192.168.53.11/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))


# UDP server
IP_A = '0.0.0.0'
PORT = 9090

# Set context
certFile = './certs/server.crt'
keyFile = './certs/server.key'
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=certFile, keyfile=keyFile)

# Setup TCP socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
timeout = 2
socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
socket.bind((IP_A, PORT))
socket.listen(5)

# We assume that sock and tun file descriptors have already been created.
ip, port = "10.9.0.5", 12345


def deal_with_client(secure_sock):
	while True:
		# this will block until at least one interface is ready
		print("waiting for ready")
		ready, _, _ = select.select([secure_sock, tun], [], [])

		for fd in ready:
			print("fd", fd)
			if fd is secure_sock:
				print("wait")
				#data, (ip, port) = secure_sock.recv(2048)
				data = secure_sock.recv(2048)
				print("received:", data)
				pkt = IP(data)
				tcp = TCP(sport=1234, dport=80, flags="S", seq=1)
				pkt = pkt / tcp
				print("packet:", pkt)
				print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
				os.write(tun, bytes(pkt))
				print("has written to tun")
			if fd is tun:
				print("waiting for tun")
				packet = os.read(tun, 2048)
				pkt = IP(packet)
				print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
				#secure_sock.sendto(packet, (ip, port))
				secure_sock.sendall(packet)



while True:
	newSocket, fromIP = socket.accept()
	# wrap the socket in a TLS/SSL layer
	secure_sock = context.wrap_socket(newSocket, server_side=True)
	try:
		deal_with_client(secure_sock)
	except Exception as e:
		print("excetion:", e)