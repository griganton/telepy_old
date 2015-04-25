import socket
import struct
from mtproto.crypt_tools import crc32
from layers.Layer import Layer


class TCPTransportLayer(Layer):
    # TODO: docstring
    def __init__(self, ip, port):
        # TODO: docstring
        self.ip = ip
        self.port = port
        self.socket = socket.socket()
        self.socket.settimeout(5.0)
        self.number = 0
        self.connect()
        Layer.__init__(self, name="TCPLayer")

    def connect(self):
        # TODO: docstring
        self.socket.connect((self.ip, self.port))

    def on_downstream_message(self, message):
        # TODO: docstring
        print("TCPLayer: sending message")
        step1 = struct.pack('<II', len(message)+12, self.number) + message
        step2 = step1 + struct.pack('<I', crc32(step1))
        self.socket.send(step2)
        self.number += 1

    def run(self):
        print("""TCPLayer: Start listening the socket""")
        while True:
            try:
                self.recv()
            except socket.timeout:
                pass

    def recv(self):
        # TODO: docstring
        packet_length_data = self.socket.recv(4)  # reads how many bytes to read

        if len(packet_length_data) < 4:
            raise Exception("Nothing in the socket! "+ packet_length_data)
        packet_length = struct.unpack("<I", packet_length_data)[0]
        packet = self.socket.recv(packet_length - 4)  # read the rest of bytes from socket
        x = struct.unpack("<I", packet[:4])
        # check the CRC32
        if not crc32(packet_length_data + packet[0:-4]) == struct.unpack('<I', packet[-4:])[0]:
            raise Exception("CRC32 was not correct!")
        payload = packet[4:-4]
        print("TCPLayer: received message" )
        self.to_upper(payload)

# TODO: Short TCP transport

# TODO: UDP transport

# TODO: Short UDP transport

# TODO: HTTP transport

