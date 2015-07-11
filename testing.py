# -*- coding: utf-8 -*-
# Deal with py2 and py3 differences
try: # this only works in py2.7
    import configparser
except ImportError:
    import ConfigParser as configparser
from layers.Crypt import CryptLayer
from layers.MessageHandler import MessageHandler
from layers.Transport import TCPTransportLayer
from layers.Session import SessionLayer
from time import sleep
from mtproto import TL

config = configparser.ConfigParser()
# Check if credentials is correctly loaded (when it doesn't read anything it returns [])
if not config.read('credentials'):
    print("File 'credentials' seems to not exist.")
    exit(-1)
ip = config.get('App data', 'ip_address')
port = config.getint('App data', 'port')

# collecting stack
tcp_transport = TCPTransportLayer(ip, port)
crypt_layer = CryptLayer(underlying_layer=tcp_transport)
session = SessionLayer(underlying_layer=crypt_layer)

i = 0
while True:
    session.method_call("ping", ping_id=i, disconnect_delay=5)
    i += 1
    sleep(2)