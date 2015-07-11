from mtproto import TL
import io

class Message:
    def __init__(self, session_id, msg_id, seq_no, message_body=None):
        self.session_id = session_id
        self.msg_id = msg_id
        self.seq_no = seq_no
        self.body = message_body

    def serialize(self):
        #print("Message: Packing data")
        assert isinstance(self.body, TL.Method) or isinstance(self.body, TL.Object)
        # Serialize
        return self.body.serialize()

    @staticmethod
    def deserialize(msg_bytes):
        # Deserialize
        ans = TL.deserialize(io.BytesIO(msg_bytes))
        #print("Message: Unpacking data")
        return ans

    @staticmethod
    def create_container(messages_list):
        msg_obj_list = [TL.Object('message', 'Message', {'session_id': message.session_id,
                                                         'msg_id': message.msg_id,
                                                         'seq_no': message.seq_no,
                                                         'body': message.body}
                                  ) for message in messages_list]
        return TL.Object('msg_container', 'MessageContainer', {'messages': msg_obj_list})
