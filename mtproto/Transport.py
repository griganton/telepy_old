__author__ = 'agrigoryev'
import socket
import struct
from mtproto.Crypt import crc32

class Transport:
    # TODO: docstring
    def __init__(self):
        self.number = 0

    def recv(self):
        pass

    def send(self, message):
        pass


class TCPTransport(Transport):
    # TODO: docstring
    def __init__(self, ip, port):
        # TODO: docstring
        Transport.__init__(self)
        self.ip = ip
        self.port = port
        self.socket = socket.socket()
        self.socket.settimeout(5.0)
        self.connect()

    def connect(self):
        # TODO: docstring
        self.socket.connect((self.ip, self.port))

    def send(self, message):
        # TODO: docstring
        step1 = struct.pack('<II', len(message)+12, self.number) + message
        step2 = step1 + struct.pack('<I', crc32(step1))
        self.socket.send(step2)
        self.number += 1

    def recv(self):
        # TODO: docstring
        packet_length_data = self.socket.recv(4)  # reads how many bytes to read

        if len(packet_length_data) < 4:
            raise Exception("Nothing in the socket!")
        packet_length = struct.unpack("<I", packet_length_data)[0]
        packet = self.socket.recv(packet_length - 4)  # read the rest of bytes from socket
        x = struct.unpack("<I", packet[:4])
        # check the CRC32
        if not crc32(packet_length_data + packet[0:-4]) == struct.unpack('<I', packet[-4:])[0]:
            raise Exception("CRC32 was not correct!")
        return packet[4:-4]

# TODO: Short TCP transport

# TODO: UDP transport

# TODO: Short UDP transport

# TODO: HTTP transport

