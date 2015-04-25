# -*- coding: utf-8 -*-

__author__ = 'agrigoryev'
from layers.Layer import Layer
from layers.Transport import TCPTransportLayer
from time import sleep


try:
    # Deal with py2 and py3 differences
    import configparser
except ImportError:
    import ConfigParser as configparser
from layers.Transport import TCPTransportLayer

config = configparser.ConfigParser()
# Check if credentials is correctly loaded (when it doesn't read anything it returns [])
if not config.read('credentials'):
    print("File 'credentials' seems to not exist.")
    exit(-1)
ip = config.get('App data', 'ip_address')
port = config.getint('App data', 'port')

transport = TCPTransportLayer(ip, port)

i=0
while i<8:
    i+=1
    S.method_call('ping', ping_id=i)
