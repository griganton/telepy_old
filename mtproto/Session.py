__author__ = 'agrigoryev'
from mtproto import Transport
from mtproto import TL
from mtproto import Crypt
from mtproto import Prime
from time import time, sleep
from mtproto.Crypt import SHA, ige_encrypt, ige_decrypt
import socket
import os
import io
import struct
import threading
import queue


class Session:
    """ Manages encryption and message frames """

    def __init__(self, transport, auth_key=None, server_salt=None):
        assert isinstance(transport, Transport.Transport)
        self.transport = transport
        self.number = 0
        self.timedelta = 0
        self.session_id = os.urandom(8)
        self.method_subscribe_dict = {}
        # creating and starting data exchange threads
        self.send_queue = queue.Queue()
        self.recv_queue = queue.Queue()
        self.pending_acks = queue.Queue()
        self.send_thread = threading.Thread(name="Sending thread", target=self.send_process)
        self.recv_thread = threading.Thread(name="Receiving thread", target=self.recv_process)
        self.subs_thread = threading.Thread(name="Subscribe thread", target=self.subs_process)
        self.send_thread.start()
        self.recv_thread.start()
        self.subs_thread.start()

        self.auth_key, self.server_salt = auth_key, server_salt
        if auth_key is None or server_salt is None:
            self.auth_key, self.server_salt = self.create_auth_key()
        self.auth_key_id = self.create_auth_key_id()

        # Subscribing functions
        self.subscribe("NewSession", self.new_session_created)

        self.future_salts = self.method_call('get_future_salts', num=3)

    def send_process(self):
        while True:
            try:
                method, parameters = self.send_queue.get(timeout=5) # 10 seconds to wait for acks
                message = TL.serialize_method(method, **parameters)
                encrypted_message = self.encrypt_message(message)
                try:
                    self.transport.send(encrypted_message)
                    print("   send: Method %s sent" % method)
                except socket.error:
                    sleep(1)
            except queue.Empty:
                # sending collected acks
                if self.pending_acks.unfinished_tasks:
                    acks=[]
                    print("Sending ack for %d messages" % self.pending_acks.qsize())
                    for i in range(self.pending_acks.qsize()):
                        ack = self.pending_acks.get_nowait()
                        self.pending_acks.task_done()
                        acks.append(ack)
                    print(acks)
                    message = TL.serialize_obj('msgs_ack', msg_ids=acks)
                    encrypted_message = self.encrypt_message(message)
                    self.transport.send(encrypted_message)
                    self.method_call('msgs_state_req', msg_ids=acks)


    def recv_process(self):
        while True:
            try:
                encrypted_message = self.transport.recv()
                server_answer = self.decrypt_message(encrypted_message)
                # Если получаем контейнер, разбиваем его на несколько частей.
                if server_answer.data.name == "msg_container":
                    print("   recv: container received:")
                    for message_box in server_answer.data['messages']:
                        message = Message(message_box['msg_id'], message_box['seqno'], message_box['body'])
                        self.recv_queue.put(message)
                        print("     %s" % message.data.name)
                else:
                        self.recv_queue.put(server_answer)
                        print("   recv: %s received" % server_answer.data.name)
            except socket.timeout:
                pass

    def subscribe(self, result_name, func):
        self.method_subscribe_dict[result_name] = func

    def subs_process(self):
        while True:
                server_answer = self.recv_queue.get()
                if self.auth_key is not None:
                    # sending acknowledge
                    print("   subs: prepare acknowledge for %s" % server_answer.msg_id)
                    self.pending_acks.put(server_answer.msg_id)
                try:
                    func  = self.method_subscribe_dict[server_answer.data.type]
                    func(server_answer)
                    print("   subs: Got object %s" % server_answer.data.type)
                except KeyError:
                    self.recv_queue.put(server_answer)
                    sleep(1)

    def wait_for_answer(self, name, timeout=5):
        q = queue.Queue()
        print("   Waiting for %s" % name)
        def got_it(server_answer):
            q.put(server_answer)
        self.subscribe(name, got_it)
        return q.get(timeout=timeout)

    def method_call(self, method, **kwargs):
         self.send_queue.put((method, kwargs))
         try:
            server_answer = self.wait_for_answer(TL.tl.method_name[method].type, timeout=5)
            return server_answer.data
         except queue.Empty:
            pass

    def new_session_created(self, server_answer):
        print("New session created")
        print(server_answer)

    def encrypt_message(self, message_data):
        # TODO: docstring
        message_id = struct.pack('<Q', int((time()+self.timedelta)*2**30)*4)
        if self.auth_key is None or self.server_salt is None:
            # Unencrypted data send
            message = (b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                       message_id +
                       struct.pack('<I', len(message_data)) +
                       message_data)
        else:
            # Encrypted data send
            encrypted_data = (self.server_salt +
                              self.session_id +
                              message_id +
                              struct.pack('<II', self.number, len(message_data)) +
                              message_data)
            message_key = SHA(encrypted_data)[-16:]
            padding = os.urandom((-len(encrypted_data)) % 16)
            aes_key, aes_iv = self.aes_calculate(message_key, direction="to server")
            message = (self.auth_key_id + message_key +
                       ige_encrypt(encrypted_data+padding, aes_key, aes_iv))
        return message

    def decrypt_message(self, packet):
        # TODO: docstring
        auth_key_id = packet[0:8]
        if auth_key_id == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            # No encryption - Plain text
            (message_id, message_length) = struct.unpack("<8sI", packet[8:20])
            data = packet[20:20+message_length]
            answer = TL.deserialize(io.BytesIO(data))
            return Message(message_id, 0, answer)
        elif auth_key_id == self.auth_key_id:
            message_key = packet[8:24]
            encrypted_data = packet[24:]
            aes_key, aes_iv = self.aes_calculate(message_key, direction="from server")
            decrypted_data = ige_decrypt(encrypted_data, aes_key, aes_iv)
            assert decrypted_data[0:8] == self.server_salt
            assert decrypted_data[8:16] == self.session_id
            message_id = struct.unpack('<Q', decrypted_data[16:24])[0]
            seq_no = struct.unpack("<I", decrypted_data[24:28])[0]
            message_data_length = struct.unpack("<I", decrypted_data[28:32])[0]
            data = decrypted_data[32:32+message_data_length]
            answer = TL.deserialize(io.BytesIO(data))
            return Message(message_id, seq_no, answer)
        else:
            raise Exception("Got unknown auth_key id %s instead of %s" % (auth_key_id, self.auth_key_id))

    def aes_calculate(self, msg_key, direction="to server"):
        # TODO: docstring
        x = (0 if direction == "to server" else 8)
        sha1_a = SHA(msg_key + self.auth_key[x:x+32])
        sha1_b = SHA(self.auth_key[x+32:x+48] + msg_key + self.auth_key[48+x:64+x])
        sha1_c = SHA(self.auth_key[x+64:x+96] + msg_key)
        sha1_d = SHA(msg_key + self.auth_key[x+96:x+128])
        aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]
        return aes_key, aes_iv


    def create_auth_key(self):

        nonce = os.urandom(16)
        print("Requesting pq")

        ResPQ = self.method_call('req_pq', nonce=nonce)
        server_nonce = ResPQ['server_nonce']

        # TODO: selecting RSA public key based on this fingerprint
        public_key_fingerprint = ResPQ['server_public_key_fingerprints'][0]

        pq_bytes = ResPQ['pq']
        pq = Crypt.bytes_to_long(pq_bytes)

        [p, q] = Prime.primefactors(pq)
        if p > q: (p, q) = (q, p)
        assert p*q == pq and p < q

        print("Factorization %d = %d * %d" % (pq, p, q))
        p_bytes = Crypt.long_to_bytes(p)
        q_bytes = Crypt.long_to_bytes(q)
        f = open(os.path.join(os.path.dirname(__file__), "rsa.pub"))
        key = Crypt.RSA.importKey(f.read())

        new_nonce = os.urandom(32)
        data = TL.serialize_obj('p_q_inner_data',
                                pq=pq_bytes,
                                p=p_bytes,
                                q=q_bytes,
                                nonce=nonce,
                                server_nonce=server_nonce,
                                new_nonce=new_nonce)

        sha_digest = Crypt.SHA(data)
        random_bytes = os.urandom(255-len(data)-len(sha_digest))
        to_encrypt = sha_digest + data + random_bytes
        encrypted_data = key.encrypt(to_encrypt, 0)[0]

        print("Starting Diffie Hellman key exchange")
        server_dh_params = self.method_call('req_DH_params',
                                            nonce=nonce,
                                            server_nonce=server_nonce,
                                            p=p_bytes,
                                            q=q_bytes,
                                            public_key_fingerprint=public_key_fingerprint,
                                            encrypted_data=encrypted_data)
        assert nonce == server_dh_params['nonce']
        assert server_nonce == server_dh_params['server_nonce']

        encrypted_answer = server_dh_params['encrypted_answer']

        tmp_aes_key = Crypt.SHA(new_nonce + server_nonce) + Crypt.SHA(server_nonce + new_nonce)[0:12]
        tmp_aes_iv = Crypt.SHA(server_nonce + new_nonce)[12:20] + Crypt.SHA(new_nonce + new_nonce) + new_nonce[0:4]

        answer_with_hash = Crypt.ige_decrypt(encrypted_answer, tmp_aes_key, tmp_aes_iv)

        answer_hash = answer_with_hash[:20]
        answer = answer_with_hash[20:]
        # TODO: SHA hash assertion here

        server_DH_inner_data = TL.deserialize(io.BytesIO(answer))
        assert nonce == server_DH_inner_data['nonce']
        assert server_nonce == server_DH_inner_data['server_nonce']
        dh_prime_str = server_DH_inner_data['dh_prime']
        g = server_DH_inner_data['g']
        g_a_str = server_DH_inner_data['g_a']
        server_time = server_DH_inner_data['server_time']
        self.timedelta = server_time - time()
        print("Server-client time delta = %.1f s" % self.timedelta)

        dh_prime = Crypt.bytes_to_long(dh_prime_str)
        g_a = Crypt.bytes_to_long(g_a_str)

        assert Prime.isprime(dh_prime)
        retry_id = 0
        b_str = os.urandom(256)
        b = Crypt.bytes_to_long(b_str)
        g_b = pow(g, b, dh_prime)

        g_b_str = Crypt.long_to_bytes(g_b)

        data = TL.serialize_obj('client_DH_inner_data',
                                nonce=nonce,
                                server_nonce=server_nonce,
                                retry_id=retry_id,
                                g_b=g_b_str)
        data_with_sha = Crypt.SHA(data) + data
        data_with_sha_padded = data_with_sha + os.urandom(-len(data_with_sha) % 16)
        encrypted_data = Crypt.ige_encrypt(data_with_sha_padded, tmp_aes_key, tmp_aes_iv)

        for i in range(1, 8): # retry when dh_gen_retry or dh_gen_fail
            set_client_dh_params_answer = self.method_call('set_client_DH_params',
                                                       nonce=nonce,
                                                       server_nonce=server_nonce,
                                                       encrypted_data=encrypted_data)
            auth_key = pow(g_a, b, dh_prime)
            auth_key_str = Crypt.long_to_bytes(auth_key)
            auth_key_sha = Crypt.SHA(auth_key_str)
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hash1 = Crypt.SHA(new_nonce+b'\x01'+auth_key_aux_hash)[-16:]
            new_nonce_hash2 = Crypt.SHA(new_nonce+b'\x02'+auth_key_aux_hash)[-16:]
            new_nonce_hash3 = Crypt.SHA(new_nonce+b'\x03'+auth_key_aux_hash)[-16:]

            assert set_client_dh_params_answer['nonce'] == nonce
            assert set_client_dh_params_answer['server_nonce'] == server_nonce

            if set_client_dh_params_answer.name == 'dh_gen_ok':
                assert set_client_dh_params_answer['new_nonce_hash1'] == new_nonce_hash1
                print("Diffie Hellman key exchange processed successfully")

                server_salt = Crypt.strxor(new_nonce[0:8], server_nonce[0:8])
                print("Auth key generated")
                return auth_key_str, server_salt
            elif set_client_dh_params_answer.name == 'dh_gen_retry':
                assert set_client_dh_params_answer['new_nonce_hash2'] == new_nonce_hash2
                print ("Retry Auth")
            elif set_client_dh_params_answer.name == 'dh_gen_fail':
                assert set_client_dh_params_answer['new_nonce_hash3'] == new_nonce_hash3
                print("Auth Failed")
                raise Exception("Auth Failed")
            else: raise Exception("Response Error")

    def set_auth_key(self, auth_key):
        self.auth_key = auth_key
        self.auth_key_id = SHA(self.auth_key)[-8:] if self.auth_key else None

    def create_auth_key_id(self):
        # TODO: docstring
        return SHA(self.auth_key)[-8:]


class Message:
    def __init__(self, msg_id, seq_no, message_data):
        self.msg_id = msg_id
        self.seq_no = seq_no
        self.data = message_data

