#!/usr/bin/env python

'''
TcpTarget is an implementation of a TCP target
'''
import socket
from kitty.targets.server import ServerTarget


class TcpTarget(ServerTarget):
    '''
    TcpTarget is implementation of a TCP target for the ServerFuzzer
    '''

    def __init__(self, name, host, port, timeout=None, logger=None):
        '''
        :param name: name of the object
        :param host: hostname of the target (the TCP server)
        :param port: port of the target
        :param timeout: socket timeout (default: None)
        :param logger: logger for this object (default: None)
        '''
        ## Call ServerTarget constructor
        super(TcpTarget, self).__init__(name, logger)
        ## hostname of the target (the TCP server)
        self.host = host
        ## port of the target
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('host and port may not be None')
        ## socket timeout (default: None)
        self.timeout = timeout
        ## the TCP socket
        self.socket = None

    def pre_test(self, test_num):
        '''
        prepare to the test, create a socket
        '''
        ## call the super (report preparation etc.)
        super(TcpTarget, self).pre_test(test_num)
        ## only create a socket if we don't have one
        if self.socket is None:
            sock = self._get_socket()
            ## set the timeout
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            ## connect to socket
            sock.connect((self.host, self.port))
            ## our TCP socket
        self.socket = sock

    def _get_socket(self):
        '''get a socket object'''
        ## Create a TCP socket
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def post_test(self, test_num):
        '''
        Called after a test is completed, perform cleanup etc.
        '''
        ## Call super, as it prepares the report
        super(TcpTarget, self).post_test(test_num)
        ## close socket
        if self.socket is not None:
            self.socket.close()
            ## set socket to none
            self.socket = None

    def _send_to_target(self, data):
        self.socket.send(data)

    def _receive_from_target(self):
        return self.socket.recv(10000)
