__author__ = 'agrigoryev'
from mtproto import TL
from layers.Layer import Layer
from mtproto.Message import Message
from mtproto.Crypt import SHA, ige_encrypt, ige_decrypt
import os
import io
import struct


def aes_calculate(auth_key, msg_key, direction="to server"):
    # TODO: docstring
    x = (0 if direction == "to server" else 8)
    sha1_a = SHA(msg_key + auth_key[x:x+32])
    sha1_b = SHA(auth_key[x+32:x+48] + msg_key + auth_key[48+x:64+x])
    sha1_c = SHA(auth_key[x+64:x+96] + msg_key)
    sha1_d = SHA(msg_key + auth_key[x+96:x+128])
    aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]
    return aes_key, aes_iv


class CryptLayer(Layer):
    def __init__(self, underlying_layer=None):
        Layer.__init__(self, name="Crypt Layer", underlying_layer=underlying_layer)
        self.auth_key = None
        self.auth_key_id = None
        self.server_salt = None

    def set_session_info(self, auth_key, server_salt):
        print("CryptLayer: got session parameters. Start sending crypted messages")
        self.auth_key = auth_key
        self.auth_key_id = SHA(self.auth_key)[-8:] if self.auth_key else None
        self.server_salt = server_salt

    def set_future_salts(self, future_salts):
        # TODO: future salts selection here
        pass

    def on_downstream_message(self, message):
        # TODO: docstring
        # Receiving Message object from Session layer:
        assert isinstance(message, Message)

        # serializing the data
        message_data = message.serialize()

        if self.auth_key is None or self.server_salt is None:
            # Unencrypted data send
            print("CryptLayer: sending plaintext message:" + message_data)
            message_bytes = (b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                             message.msg_id +
                             struct.pack('<I', len(message_data)) +
                             message_data)
        else:
            # Encrypted data send
            print("CryptLayer: sending crypted message:" + message.body)
            encrypted_data = (self.server_salt +
                              message.session_id +
                              message.msg_id +
                              struct.pack('<II', message.seq_no, len(message.body)) +
                              message.body)
            message_key = SHA(encrypted_data)[-16:]
            padding = os.urandom((-len(encrypted_data)) % 16)
            aes_key, aes_iv = aes_calculate(self.auth_key, message_key, direction="to server")
            message_bytes = (self.auth_key_id + message_key +
                             ige_encrypt(encrypted_data+padding, aes_key, aes_iv))
        # sending crypted message bytes to transport layer
        self.to_lower(message_bytes)

    def on_upstream_message(self, packet):
        """ Receiving message from transport layer"""
        # TODO: docstring
        auth_key_id = packet[0:8]
        if auth_key_id == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            # No encryption - Plain text
            (message_id, message_length) = struct.unpack("<8sI", packet[8:20])
            data = packet[20:20+message_length]

            # deserializing data
            answer = Message.deserialize(data)

            # Sending message to upper layer
            self.to_upper(Message(session_id=None,
                                  msg_id=message_id,
                                  seq_no=None,
                                  message_body=answer))

        elif auth_key_id == self.auth_key_id:
            message_key = packet[8:24]
            encrypted_data = packet[24:]
            aes_key, aes_iv = aes_calculate(self.auth_key, message_key, direction="from server")
            decrypted_data = ige_decrypt(encrypted_data, aes_key, aes_iv)
            server_salt = decrypted_data[0:8]
            assert server_salt == self.server_salt
            session_id = decrypted_data[8:16]
            message_id = struct.unpack('<Q', decrypted_data[16:24])[0]
            seq_no = struct.unpack("<I", decrypted_data[24:28])[0]
            message_data_length = struct.unpack("<I", decrypted_data[28:32])[0]
            data = decrypted_data[32:32+message_data_length]

            # deserializing data
            answer = Message.deserialize(data)

            # Sending message to upper layer
            self.to_upper(Message(session_id=session_id,
                                  msg_id=message_id,
                                  seq_no=seq_no,
                                  message_body=answer))
        else:
            raise Exception("Got unknown auth_key id")