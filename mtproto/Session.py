__author__ = 'agrigoryev'
from mtproto import Transport
from mtproto import TL
from mtproto import crypt_tools
from mtproto import prime
from time import time, sleep
from mtproto.crypt_tools import SHA, ige_encrypt, ige_decrypt
from mtproto.Message import Message
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
        self.seq_no = 0
        self.timedelta = 0
        self.session_id = os.urandom(8)
        self.method_subscribe_dict = {}
        # creating and starting data exchange threads
        self.send_queue = queue.Queue()
        self.recv_queue = queue.Queue()
        self.pending_acks = []
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
                # Wait 10 seconds and sending acks
                # if we get acks, create and send message container
                # if there is no pending acks, send only message
                method, parameters = self.send_queue.get(timeout=10)
                message = TL.serialize_method(method, **parameters)
                encrypted_message = self.encrypt_message(message)
                try:
                    self.transport.send(encrypted_message)
                    print("   send: Method %s sent" % method)
                except socket.error:
                    sleep(1)
            except queue.Empty:
                # if we have nothing to send, just sending all pending message acks
                if self.pending_acks:
                    print(self.pending_acks)
                    message = TL.serialize_obj('msgs_ack', msg_ids=self.pending_acks)
                    encrypted_message = self.encrypt_message(message)
                    self.transport.send(encrypted_message)
                    self.pending_acks = []


    def recv_process(self):
        """ Ждет сообщений из сокета и складывает в очередь """
        while True:
            try:
                encrypted_message = self.transport.recv()
                server_answer = self.decrypt_message(encrypted_message)
                if self.auth_key is not None:
                    # sending acknowledge
                    print("   subs: prepare acknowledge for %s" % server_answer.msg_id)
                    self.pending_acks.append(server_answer.msg_id)
                # Если получаем контейнер, разбиваем его на несколько частей.
                if server_answer.data.name == "msg_container":
                    print("   recv: Сontainer with contents:")
                    for message_box in server_answer.data['messages']:
                        message = Message(message_box['msg_id'], message_box['seqno'], message_box['body'])
                        self.recv_queue.put(message)
                        print("        %s" % message.data.type)
                else:
                        self.recv_queue.put(server_answer)
                        print("   recv: %s received" % server_answer.data.type)
                        print(server_answer.data)
            except socket.timeout:
                pass

    def subscribe(self, result_name, func):
        self.method_subscribe_dict[result_name] = func

    def subs_process(self):
        while True:
            try:
                sleep(1)
                server_answer = self.recv_queue.get()
                try:
                    func  = self.method_subscribe_dict[server_answer.data.type]
                    func(server_answer)
                    print("   subs: Got object %s" % server_answer.data.type)
                except KeyError:
                    #self.recv_queue.put(server_answer)
                    pass
            except queue.Empty:
                pass

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

    def create_auth_key(self):
        nonce = os.urandom(16)
        print("Requesting pq")

        ResPQ = self.method_call('req_pq', nonce=nonce)
        server_nonce = ResPQ['server_nonce']

        # TODO: selecting RSA public key based on this fingerprint
        public_key_fingerprint = ResPQ['server_public_key_fingerprints'][0]

        pq_bytes = ResPQ['pq']
        pq = crypt_tools.bytes_to_long(pq_bytes)

        [p, q] = prime.primefactors(pq)
        if p > q: (p, q) = (q, p)
        assert p*q == pq and p < q

        print("Factorization %d = %d * %d" % (pq, p, q))
        p_bytes = crypt_tools.long_to_bytes(p)
        q_bytes = crypt_tools.long_to_bytes(q)
        f = open(os.path.join(os.path.dirname(__file__), "rsa.pub"))
        key = crypt_tools.RSA.importKey(f.read())

        new_nonce = os.urandom(32)
        data = TL.serialize_obj('p_q_inner_data',
                                pq=pq_bytes,
                                p=p_bytes,
                                q=q_bytes,
                                nonce=nonce,
                                server_nonce=server_nonce,
                                new_nonce=new_nonce)

        sha_digest = crypt_tools.SHA(data)
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

        tmp_aes_key = crypt_tools.SHA(new_nonce + server_nonce) + crypt_tools.SHA(server_nonce + new_nonce)[0:12]
        tmp_aes_iv = crypt_tools.SHA(server_nonce + new_nonce)[12:20] + crypt_tools.SHA(new_nonce + new_nonce) + new_nonce[0:4]

        answer_with_hash = crypt_tools.ige_decrypt(encrypted_answer, tmp_aes_key, tmp_aes_iv)

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

        dh_prime = crypt_tools.bytes_to_long(dh_prime_str)
        g_a = crypt_tools.bytes_to_long(g_a_str)

        assert prime.isprime(dh_prime)
        retry_id = 0
        b_str = os.urandom(256)
        b = crypt_tools.bytes_to_long(b_str)
        g_b = pow(g, b, dh_prime)

        g_b_str = crypt_tools.long_to_bytes(g_b)

        data = TL.serialize_obj('client_DH_inner_data',
                                nonce=nonce,
                                server_nonce=server_nonce,
                                retry_id=retry_id,
                                g_b=g_b_str)
        data_with_sha = crypt_tools.SHA(data) + data
        data_with_sha_padded = data_with_sha + os.urandom(-len(data_with_sha) % 16)
        encrypted_data = crypt_tools.ige_encrypt(data_with_sha_padded, tmp_aes_key, tmp_aes_iv)

        for i in range(1, 8): # retry when dh_gen_retry or dh_gen_fail
            set_client_dh_params_answer = self.method_call('set_client_DH_params',
                                                       nonce=nonce,
                                                       server_nonce=server_nonce,
                                                       encrypted_data=encrypted_data)
            auth_key = pow(g_a, b, dh_prime)
            auth_key_str = crypt_tools.long_to_bytes(auth_key)
            auth_key_sha = crypt_tools.SHA(auth_key_str)
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hash1 = crypt_tools.SHA(new_nonce+b'\x01'+auth_key_aux_hash)[-16:]
            new_nonce_hash2 = crypt_tools.SHA(new_nonce+b'\x02'+auth_key_aux_hash)[-16:]
            new_nonce_hash3 = crypt_tools.SHA(new_nonce+b'\x03'+auth_key_aux_hash)[-16:]

            assert set_client_dh_params_answer['nonce'] == nonce
            assert set_client_dh_params_answer['server_nonce'] == server_nonce

            if set_client_dh_params_answer.name == 'dh_gen_ok':
                assert set_client_dh_params_answer['new_nonce_hash1'] == new_nonce_hash1
                print("Diffie Hellman key exchange processed successfully")

                server_salt = crypt_tools.strxor(new_nonce[0:8], server_nonce[0:8])
                print("Auth key generated")
                return auth_key_str, server_salt
            elif set_client_dh_params_answer.name == 'dh_gen_retry':
                assert set_client_dh_params_answer['new_nonce_hash2'] == new_nonce_hash2
                print ("Retry Auth")
            elif set_client_dh_params_answer.name == 'dh_gen_fail':
                assert set_client_dh_params_answer['new_nonce_hash3'] == new_nonce_hash3
                print("Auth Failed")
                raise Exception("Auth Failed")
            else:
                raise Exception("Response Error")

    def set_auth_key(self, auth_key):
        self.auth_key = auth_key
        self.auth_key_id = SHA(self.auth_key)[-8:] if self.auth_key else None

    def create_auth_key_id(self):
        # TODO: docstring
        return SHA(self.auth_key)[-8:]

