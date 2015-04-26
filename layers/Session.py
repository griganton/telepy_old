from layers.Layer import Layer
from mtproto.Message import Message
from mtproto import crypt_tools
from mtproto import prime
from mtproto import TL
from time import time, sleep

import queue
import os
import io


class SessionLayer(Layer):
    """ Manages encryption and message frames """
    def __init__(self, auth_key=None, server_salt=None, underlying_layer=None):
        self.seq_no = 0
        self.timedelta = 0
        self.session_id = os.urandom(8)
        self.future_salts = []
        self.__subscribe_dict = {}
        self.auth_key, self.server_salt = auth_key, server_salt

        Layer.__init__(self, name="Session Layer", underlying_layer=underlying_layer)
        self.subscribe('NewSession', self.new_session_created)
        self.subscribe('MessageContainer', self.on_message_container)

        # creating and starting data exchange threads

        if auth_key is None or server_salt is None:
            self.auth_key, self.server_salt = self.create_auth_key()
        self.auth_key_id = crypt_tools.SHA(self.auth_key)[-8:]

        # Propagate authorization to Crypt layer
        self.underlying_layer.set_session_info(self.auth_key, self.server_salt)

        # Acquire session ID and get future salts:

    def on_upstream_message(self, message):
        print("Session: got message %s" % message.body.type)
        if message.body.type in self.__subscribe_dict.keys():
            func = self.__subscribe_dict[message.body.type]
            func(message)
        else:
            self.to_upper(message)

    def new_session_created(self, message):
        print("Session: got new session from server")
        self.server_salt = crypt_tools.long_to_bytes(message.body['server_salt'])
        #self.session_id = crypt_tools.long_to_bytes(message.body['unique_id'])
        self.seq_no = 0

    def method_call(self, predicate, **kwargs):
        return_type = TL.tl.method_name[predicate].type
        self.send(TL.Method(predicate, return_type, kwargs))
        q = queue.Queue()
        # print("   Waiting for '%s' answer" % return_type)
        def got_it(server_answer):
            q.put(server_answer)
        self.subscribe(return_type, got_it)
        try:
            return q.get(timeout=2.0).body
        except queue.Empty:
            print("Session: Can't get answer %s on method %s" % (return_type, predicate))

    def update_session_salt(self):
        # updating future salts in case if it is empty or last future_salt used
        if not self.future_salts or self.future_salts[-1]['valid_since'] <= time():
            future_salts_msg = self.method_call("get_future_salts", num=3)
            print("Session: got future salts" + str(future_salts_msg))
            for salt in future_salts_msg['salts']:
                self.future_salts.append(salt.params)

        for future_salt in self.future_salts[::-1]:
            if future_salt['valid_since'] <= time() <= future_salt['valid_until']:
                if self.server_salt != future_salt['salt']:
                    print("Session: Salt updated")
                    self.server_salt = future_salt['salt']
                break

    def run(self):
        while True:
            if self.auth_key is not None:
                self.update_session_salt()
            sleep(60)

    def send(self, tl_object):
        message_id = int((time() + self.timedelta)*2**30)*4
        # Select salt
        message = Message(session_id=self.session_id,
                          msg_id=message_id,
                          seq_no=self.seq_no,
                          message_body=tl_object)
        print("Session: send message %s" % tl_object.predicate)
        self.to_lower(message)

    def create_auth_key(self):
        nonce = os.urandom(16)
        print("Session: Requesting pq")

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
        print("Session: Server-client time delta = %.1f s" % self.timedelta)

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
                print("Session: Diffie Hellman key exchange processed successfully")

                server_salt = crypt_tools.strxor(new_nonce[0:8], server_nonce[0:8])
                print("Session: Auth key generated")
                return auth_key_str, server_salt
            elif set_client_dh_params_answer.name == 'dh_gen_retry':
                assert set_client_dh_params_answer['new_nonce_hash2'] == new_nonce_hash2
                print("Session: Retry Auth")
            elif set_client_dh_params_answer.name == 'dh_gen_fail':
                assert set_client_dh_params_answer['new_nonce_hash3'] == new_nonce_hash3
                print("Session: Auth Failed")
                raise Exception("Auth Failed")
            else:
                raise Exception("Response Error")

    def on_message_container(self, message):
        print("Session: Received container with contents:")
        for message_box in message.body['messages']:
            # If we have got message container, we should unpack it to separate messages and send upper.
            # So, if message container is empty, nothing will be sent upper.
            print("       - %s" % message_box['body'].type)
            message_from_box = Message(session_id=message.session_id,
                                       msg_id=message_box['msg_id'],
                                       seq_no=message_box['seqno'],
                                       message_body=message_box['body'])
            self.underlying_layer.upstream_queue.put(message_from_box)

    def subscribe(self, type_, func):
        self.__subscribe_dict[type_] = func