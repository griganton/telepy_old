# -*- coding: utf-8 -*-
# Deal with py2 and py3 differences
try: # this only works in py2.7
    import configparser
except ImportError:
    import ConfigParser as configparser
from mtproto.Session import Session
from mtproto.Transport import TCPTransport
from time import sleep
from mtproto import TL

config = configparser.ConfigParser()
# Check if credentials is correctly loaded (when it doesn't read anything it returns [])
if not config.read('credentials'):
    print("File 'credentials' seems to not exist.")
    exit(-1)
ip = config.get('App data', 'ip_address')
port = config.getint('App data', 'port')

message = TL.serialize_obj('msgs_ack', msg_ids=[1,2,3])

server1 = TCPTransport(ip, port)
S = Session(transport=server1)
S.timedelta = -10000
S.method_call('ping', ping_id=0)