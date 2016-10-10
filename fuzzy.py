import socket
from kitty.targets.server import ServerTarget
from kitty.controllers.base import BaseController
from kitty.model import *

####################################
# About this file
####################################
# There are three broad parts to the fuzzer, written using the Kitty framework:
#
# 1) Data model
# 2) Target
# 3) Controller
#
# Lastly is the actual fuzzer runner code.
#

################# Data Model #################

http_get_request = Template(name='HTTP_GET_V3', fields=[
    String('GET', name='method', fuzzable=False),   # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),  # 1.a The space between Method and Path
    String('/index.html', name='path'),             # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),                  # 2.a. The space between Path and Protocol
    String('HTTP', name='protocol name'),           # 3.a Protocol Name - a string with the value "HTTP"
    Delimiter('/', name='fws1'),                    # 3.b The '/' after "HTTP"
    Dword(1, name='major version',                  # 3.c Major Version - a number with the value 1
          encoder=ENC_INT_DEC)                      # encode the major version as decimal number
    Delimiter('.', name='dot1'),                    # 3.d The '.' between 1 and 1
    Dword(1, name='major version',                  # 3.e Minor Version - a number with the value 1
          encoder=ENC_INT_DEC)                      # encode the minor version as decimal number
    Static('\r\n\r\n', name='eom')                  # 4. The double "new lines" ("\r\n\r\n") at the end of the request
])

################# Target #################

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

################# Controller Implementation #################

class LocalProcessController(BaseController):
    '''
    LocalProcessController a process that was opened using subprocess.Popen.
    The process will be created for each test and killed at the end of the test
    '''

    def __init__(self, name, process_path, process_args, logger=None):
        '''
        :param name: name of the object
        :param process_path: path to the target executable
        :param process_args: arguments to pass to the process
        :param logger: logger for this object (default: None)
        '''
        super(ClientProcessController, self).__init__(name, logger)
        assert(process_path)
        assert(os.path.exists(process_path))
        self._process_path = process_path
        self._process_name = os.path.basename(process_path)
        self._process_args = process_args
        self._process = None

################# Actual fuzzer code #################
target = TcpTarget('Example Target')

controller = MyClientController()
target.set_controller(controller)

model = GraphModel()
model.connect(get_name_response_template)
fuzzer = ClientFuzzer()
fuzzer.set_model(model)
fuzzer.set_target(target)
fuzzer.set_interface(WebInterface())

my_stack = MySpecialStack()
my_stack.set_fuzzer(fuzzer)
fuzzer.start()
my_stack.start()
