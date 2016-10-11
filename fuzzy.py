#!/usr/bin/env python
import socket
import time
import traceback
from kitty.model import *
from kitty.targets.server import ServerTarget
from kitty.fuzzers import ServerFuzzer
from kitty.controllers.base import BaseController
from katnip.controllers.client.process import ClientProcessController
from kitty.interfaces import WebInterface


####################################
# About this file
####################################
# There are three broad parts to this kitty-based fuzzer:
#
# 1) Data model
# 2) Target
# 3) Controller
#
# Lastly is the actual fuzzer runner code.
#

################# Data Model #################

http_get_request_template = Template(name='HTTP_GET_V3', fields=[
    String('GET', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
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


    def pre_test(self, test_num):
        '''start the victim'''
        ## stop the process if it still runs for some reason
        if self._process:
            self._stop_process()
        cmd = [self._process_path] + self._process_args
        ## start the process
        self._process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        ## add process information to the report
        self.report.add('process_name', self._process_name)
        self.report.add('process_path', self._process_path)
        self.report.add('process_args', self._process_args)
        self.report.add('process_id', self._process.pid)


    def post_test(self):
        '''Called when test is done'''
        self._stop_process()
        ## Make sure process started by us
        assert(self._process)
        ## add process information to the report
        self.report.add('stdout', self._process.stdout.read())
        self.report.add('stderr', self._process.stderr.read())
        self.logger.debug('return code: %d', self._process.returncode)
        self.report.add('return_code', self._process.returncode)
        ## if the process crashed, we will have a different return code
        self.report.add('failed', self._process.returncode != 0)
        self._process = None
        ## call the super
        super(ClientProcessController, self).post_test()

    def teardown(self):
        '''
        Called at the end of the fuzzing session, override with victim teardown
        '''
        self._stop_process()
        self._process = None
        super(ClientProcessController, self).teardown()

    def _stop_process(self):
        if self._is_victim_alive():
            self._process.terminate()
            time.sleep(0.5)
            if self._is_victim_alive():
                self._process.kill()
                time.sleep(0.5)
                if self._is_victim_alive():
                    raise Exception('Failed to kill client process')

    def _is_victim_alive(self):
        return self._process and (self._process.poll() is None)

################# Actual fuzzer runner code #################
target = TcpTarget('Example Target', 'localhost', 8080)

# Define controller
#controller = LocalProcessController('Example Controller', 'lswsctrl', '/home/jz/root/bin/', '')
env = os.environ.copy()
controller = ClientProcessController(
        'ServerController',
        '/home/jz/root/bin/lswsctrl',
        ['http://localhost:8082/fuzzed'],
        process_env=env
    )

target.set_controller(controller)

# Define model
model = GraphModel()
model.connect(http_get_request_template)

# Define fuzzer
fuzzer = ServerFuzzer()
fuzzer.set_model(model)
fuzzer.set_target(target)
fuzzer.set_interface(WebInterface(host='0.0.0.0', port=26000))
#fuzzer.set_delay_between_tests(0.2)
fuzzer.start()
