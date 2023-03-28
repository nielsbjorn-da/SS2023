import socket
import struct
from Crypto.Cipher import AES
from secrets import secret_key

ICMP_TIME_FORMAT = "!d"  # d=double

def decrypt(ciphertext: bytes):
    nonce = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(secret_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(actual_ciphertext)
    return plaintext

if __name__ == '__main__':
    HOST = socket.gethostbyname(socket.gethostname())
    #HOST = "localhost"
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print("IP address: ", HOST)
    while True:
        data, addr = s.recvfrom(1024)
        print("\nReceived packet from ", addr)
        icmp_header = data[20:28]
        #https://stackoverflow.com/questions/8245344/python-icmp-socket-server-not-tcp-udp
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        print("ICMP header: type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]")
        #print(data[28:])
        plaintext = decrypt(data[28:])
        print("Message received:", plaintext)
        #print(data[28:].decode())
