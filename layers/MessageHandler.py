__author__ = 'agrigoryev'
from layers.Layer import Layer
from mtproto.Message import Message
class MessageHandler(Layer):
    """ Handles messages - packing and unpacking message containers, sending message acks"""
    # TODO: gzipped data support
    # https://core.telegram.org/mtproto/service_messages#packed-object
    # TODO: message acks
    # https://core.telegram.org/mtproto/service_messages_about_messages#acknowledgment-of-receipt
    # TODO: message id buffer and checks

    def __init__(self, underlying_layer=None):
        Layer.__init__(self, underlying_layer=underlying_layer)
        self.pending_acks = []

    def on_downstream_message(self, message):
        # TODO: attach pending message acks to downstream message
        print("Message handler: sending message")
        self.to_lower(message)

    def on_upstream_message(self, message):
        assert isinstance(message, Message)
        if message.body.type == "msg_container":
            print("Message handler: Сontainer with contents:")
            print("   recv: Сontainer with contents:")
            for message_box in message.body.data['messages']:
                # If we have got message container, we should unpack it to separate messages and send upper.
                # So, if message container is empty, nothing will be sent upper.
                print("        %s" % message.body.type)
                message_from_box = Message(session_id=message.session_id,
                                           msg_id=message_box['msg_id'],
                                           seq_no=message_box['seqno'],
                                           message_body=message_box['body'])
                self.to_upper(message_from_box)
                # Every message from container have to be acknowledged
                if message_from_box.msg_id is not None:
                    self.pending_acks.append(message_from_box.msg_id)
        else:
            print("Message handler: received message")
            # not a container
            self.to_upper(message)
            # Crypted message has to be acknowledged
            if message.msg_id is not None:
                self.pending_acks.append(message.msg_id)

# Containers are messages containing several other messages.
# Used for the ability to transmit several RPC queries and/or service messages at the same time,
# using HTTP or even TCP or UDP protocol. A container may only be accepted or rejected by the other
# party as a whole. An acknowledgment for a container automatically serves as an acknowledgment for
# all the included messages.
#
# A simple container carries several messages as follows:
# msg_container#73f1f8dc messages:vector message = MessageContainer;
#
# Here message refers to any message together with its length and msg_id:
# message msg_id:long seqno:int bytes:int body:Object = Message;
# bytes is the number of bytes in the body serialization.
#
# All messages in a container must have msg_id lower than that of the container itself.
# A container does not require an acknowledgment and may not carry other simple containers.
# When messages are re-sent, they may be combined into a container in a different manner or sent individually.
#
# Empty containers are also allowed.
# They are used by the server, for example, to respond to an HTTP request
# when the timeout specified in http_wait expires, and there are no messages to transmit.
