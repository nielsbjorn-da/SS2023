import sys
from ping3 import ping
import socket
import struct
import os
import threading
import zlib
from Crypto.Cipher import AES
from secrets import secret_key

ICMP_HEADER_FORMAT = "!BBHHH"
ICMP_TYPE = 47
ICMP_ECHO_CODE = 0
ICMP_TIME_FORMAT = "!d"  # d=double

def checksum(source: bytes) -> int:
    """Calculates the checksum of the input bytes.
    RFC1071: https://tools.ietf.org/html/rfc1071
    RFC792: https://tools.ietf.org/html/rfc792
    Args:
        source: Bytes. The input to be calculated.
    Returns:
        int: Calculated checksum.
    """
    BITS = 16  # 16-bit long
    carry = 1 << BITS  # 0x10000
    result = sum(source[::2]) + (sum(source[1::2]) << (BITS // 2))  # Even bytes (odd indexes) shift 1 byte to the left.
    while result >= carry:  # Ones' complement sum.
        result = sum(divmod(result, carry))  # Each carry add to right most bit.
    return ~result & ((1 << BITS) - 1)  # Ensure 16-bit

def send_one_icmp(sock: socket, dest_addr: str, icmp_id: int, seq: int, message: bytes):
    """Sends one ping to the given destination.
    ICMP Header (bits): type (8), code (8), checksum (16), id (16), sequence (16)
    ICMP Payload: time (double), data
    ICMP Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    Args:
        sock: Socket.
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        icmp_id: ICMP packet id. Calculated from Process ID and Thread ID.
        seq: ICMP packet sequence, usually increases from 0 in the same process.
        size: The ICMP packet payload size in bytes. Note this is only for the payload part.
    Raises:
        HostUnkown: If destination address is a domain name and cannot resolved.
    """
    try:
        dest_addr = socket.gethostbyname(dest_addr)  # Domain name will translated into IP address, and IP address leaves unchanged.
    except socket.gaierror as err:
        raise Exception
    pseudo_checksum = 0  # Pseudo checksum is used to calculate the real checksum.
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, ICMP_TYPE, ICMP_ECHO_CODE, pseudo_checksum, icmp_id, seq)
    #padding = (size - struct.calcsize(ICMP_TIME_FORMAT)) * "Q"  # Using double to store current time.
    icmp_payload = message #struct.pack(ICMP_TIME_FORMAT, time.time()) #+ padding.encode()
    real_checksum = checksum(icmp_header + icmp_payload)  # Calculates the checksum on the dummy header and the icmp_payload.
    # Don't know why I need socket.htons() on real_checksum since ICMP_HEADER_FORMAT already in Network Bytes Order (big-endian)
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, ICMP_TYPE, ICMP_ECHO_CODE, socket.htons(real_checksum), icmp_id, seq)  # Put real checksum into ICMP header.
    packet = icmp_header + icmp_payload
    sock.sendto(packet, (dest_addr, 0))  # addr = (ip, port). Port is 0 respectively the OS default behavior will be used.

def icmp(dest_addr: str, seq: int = 0, message: bytes = b'') -> float:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError as err:
        raise err
    thread_id = threading.get_native_id() if hasattr(threading, 'get_native_id') else threading.currentThread().ident  # threading.get_native_id() is supported >= python3.8.
    process_id = os.getpid()  # If ping() run under different process, thread_id may be identical.
    icmp_id = zlib.crc32("{}{}".format(process_id, thread_id).encode()) & 0xffff  # to avoid icmp_id collision.
    try:
        send_one_icmp(sock=sock, dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, message=message)
    except Exception as err:
       raise Exception
    
def encrypt(plaintext: str):
    plain_bytes = plaintext.encode()
    cipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext = cipher.encrypt(plain_bytes)
    return cipher.nonce + ciphertext

if __name__ == '__main__':
    HOST = sys.argv[1]
    print("IP address: ", HOST)
    while True:
        message = input("\nWrite a message: ")
        print(message)
        c = encrypt(message)
        print("Encrypted:", c)
        icmp(HOST, message=c)
        
        