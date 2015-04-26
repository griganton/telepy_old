import socket
import struct
from mtproto.crypt_tools import crc32
from layers.Layer import Layer
from time import sleep

class TCPTransportLayer(Layer):
    # TODO: docstring
    def __init__(self, ip, port):
        # TODO: docstring
        self.ip = ip
        self.port = port
        self.socket = socket.socket()
        self.socket.settimeout(5.0)
        self.send_number = 0
        self.recv_number = 0
        self.connect()
        Layer.__init__(self, name="TCPLayer")

    def connect(self):
        # TODO: docstring
        self.socket.connect((self.ip, self.port))

    def on_downstream_message(self, message):
        # TODO: docstring
        # print("TCPLayer: sending message #%d in TCP session" % self.send_number)
        step1 = struct.pack('<II', len(message)+12, self.send_number) + message
        step2 = step1 + struct.pack('<I', crc32(step1))
        self.socket.send(step2)
        self.send_number += 1

    def run(self):
       #  print("""TCPLayer: Start listening the socket""")
        while True:
            try:
                self.recv()
                sleep(0.1)
            except (ConnectionAbortedError, OSError):
                print("TCPLayer: Connection aborted. Reconnecting...")
                while True:
                    try:
                        self.socket.close()
                        self.socket = socket.socket()
                        self.connect()
                        break
                    except OSError:
                        sleep(0.1)

            except socket.timeout:
                pass

    def recv(self):
        # TODO: docstring
        packet_length_data = self.socket.recv(4)  # reads how many bytes to read
        if len(packet_length_data) == 4:
            packet_length = struct.unpack("<I", packet_length_data)[0]
            packet = self.socket.recv(packet_length - 4)  # read the rest of bytes from socket
            self.recv_number = struct.unpack("<I", packet[:4])
            # check the CRC32
            if crc32(packet_length_data + packet[0:-4]) == struct.unpack('<I', packet[-4:])[0]:
                payload = packet[4:-4]
                # print("TCPLayer: received message #%d in TCP session" % self.recv_number)
                self.to_upper(payload)

# TODO: Short TCP transport

# TODO: UDP transport

# TODO: Short UDP transport

# TODO: HTTP transport
