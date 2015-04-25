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
        Layer.__init__(self, name="Session Layer", underlying_layer=underlying_layer)
        self.seq_no = 0
        self.timedelta = 0
        self.session_id = os.urandom(8)
        self.subs_queue = queue.Queue()
        self.method_subscribe_dict = {}

        # creating and starting data exchange threads
        self.auth_key, self.server_salt = auth_key, server_salt
        if auth_key is None or server_salt is None:
            self.auth_key, self.server_salt = self.create_auth_key()
        self.auth_key_id = self.create_auth_key_id()

    def subscribe(self, result_name, func):
        self.method_subscribe_dict[result_name] = func


    def run(self):
        while True:
            try:
                sleep(1)
                server_answer = self.subs_queue.get()
                try:
                    func = self.method_subscribe_dict[server_answer.body.type]
                    func(server_answer)
                    print("   subs: Got object %s" % server_answer.body.type)
                except KeyError:
                    pass
            except queue.Empty:
                pass

    def wait_for_answer(self, name, timeout=5):
        q = queue.Queue()
        print("   Waiting for %s" % name)
        def got_it(server_answer):
            q.put(server_answer)
        self.subscribe(name, got_it)
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

    def method_call(self, predicate, **kwargs):
        return_type = TL.tl.method_name[predicate].type
        self.send(TL.Method(predicate, return_type, kwargs))
        answer = self.wait_for_answer(return_type)
        return answer.body

    def on_upstream_message(self, message):
        self.subs_queue.put(message)

    def set_auth_key(self, auth_key):
        self.auth_key = auth_key
        self.auth_key_id = crypt_tools.SHA(self.auth_key)[-8:] if self.auth_key else None

    def create_auth_key_id(self):
        # TODO: docstring
        return crypt_tools.SHA(self.auth_key)[-8:]

    def send(self, tl_object):
        message_id = int((time() + self.timedelta)*2**30)*4
        message = Message(session_id=self.session_id,
                          msg_id=message_id,
                          seq_no=self.seq_no,
                          message_body=tl_object)
        print("Session: send message %s type" % tl_object.return_type)
        self.to_lower(message)

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


