#!/usr/bin/env python
import socket
import time
import traceback
from subprocess import *
from kitty.targets.server import ServerTarget
from kitty.model import *
from kitty.fuzzers import ServerFuzzer
from kitty.controllers.base import BaseController
# from katnip.controllers.client.process import MyController
from katnip.targets.tcp import TcpTarget
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

################# Data Models #################
"""
http_get_request_template = Template(name='HTTP_GET_TEMPLATE', fields=[
    String('GET', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])
"""
http_get_request_template_1 = Template(name='HTTP_GET_REQUEST_V1', fields=[
    String('GET', name='method', fuzzable= False),               
    Delimiter(' ', name='space1', fuzzable= False),              
    String('/index.html', name='path'),         
    Delimiter(' ', name='space2'),             
    String('HTTP', name='protocol name'),      
    Delimiter('/', name='fws1'),               
    Dword(1, name='major version', encoder=ENC_INT_DEC),
    Delimiter('.', name='dot1'),               
    Dword(1, name='minor version', encoder=ENC_INT_DEC),
    Delimiter('\r\n\r\n', name='eom'),
 
])

http_get_request_template_2 = Template(name='HTTP_GET_REQUEST_V2', fields=[
    String('GET', name='method', fuzzable= False),               
    Delimiter(' ', name='space1', fuzzable= False),              
    String('/index.html', name='path'),         
    Delimiter(' ', name='space2'),             
    String('HTTP', name='protocol name'),      
    Delimiter('/', name='fws1'),               
    Dword(1, name='major version', encoder=ENC_INT_DEC),
    Delimiter('.', name='dot1'),               
    Dword(1, name='minor version', encoder=ENC_INT_DEC),
    Delimiter('\r\n', name='newLine1'),
    String('Host:', name='host field'),
    Delimiter(' ', name='space3', fuzzable= False),  
    String('www.google.com', name='hostURL'),
    Delimiter('\r\n', name='newLine2'),
    String('User-Agent:', name='user-agent field'),
    Delimiter(' ', name='space4', fuzzable= False),  
    String('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.2) Gecko/20030208 Netscape/7.02', name='browser type'),
    Delimiter('\r\n', name='newLine3'),
    String('Accept:', name='accept field'),
    Delimiter(' ', name='space5', fuzzable= False),  
    String('text/xml,text/html;q=0.9,text/plain;q=0.8', name='accept values'),
    Delimiter('\r\n', name='newLine4'),
    String('Accept-language:', name='Accept-language field'),
    Delimiter(' ', name='space6', fuzzable= False),  
    String('en-us, en;q=0.50', name='Accept-language values'),
    Delimiter('\r\n', name='newLine5'),
    String('Keep-Alive:', name='Keep-Alive field'),
    Delimiter(' ', name='space7', fuzzable= False),  
    Dword(300, name='timeToLive', encoder=ENC_INT_DEC),
    Delimiter('\r\n', name='newLine6'),
    String('Connection:', name='Connection field'),
    Delimiter(' ', name='space8', fuzzable= False),  
    String('Keep-Alive', name='Connection state'),
    Delimiter('\r\n', name='newLine7'),
    String('Content-length:', name='Content-length field'),
    Delimiter(' ', name='space9', fuzzable= False),  
    Dword(163411, name='content-size', encoder=ENC_INT_DEC),
    Delimiter('\r\n\r\n', name='eom', fuzzable= False),
 
])

################# Target #################

# using the TcpTarget already implemented in katnip

################# Controller Implementation #################

class MyController(BaseController):
    '''
    MyController is a process that was opened using subprocess.Popen.
    The process will be created for each test and killed at the end of the test
    '''
    
    _server_start_cmd = ""
    _server_stop_cmd = ""

    def __init__(self, name, main_process_path,
                server_start_cmd,
                server_stop_cmd,
                process_args,
                process_env,
                logger=None):
        '''
        :param name: name of the object
        :param process_path: path to the target executable
        :param process_args: arguments to pass to the process
        :param logger: logger for this object (default: None)
        '''
        super(MyController, self).__init__(name, logger)
        assert(main_process_path)
        assert(os.path.exists(main_process_path))
        if process_env is None:
            process_env = os.environ.copy()
        self._process_path = main_process_path
        self._process_name = os.path.basename(main_process_path)
        self._process_args = process_args
        self._process = None
        self._process_env = process_env
        self._server_start_cmd = server_start_cmd
        self._server_stop_cmd = server_stop_cmd 

    def pre_test(self, test_number):
        ## call the super
        super(MyController, self).pre_test(test_number)

        '''start the victim'''
        ## stop the process if it still runs for some reason
        if self._process:
            self._stop_process()

        ## start the process
        self._process = Popen(self._server_start_cmd, stdout=PIPE, stderr=PIPE)

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
        ##self.report.add('failed', self._process.returncode != 0)
        ##self._process = None
        ## call the super
        super(MyController, self).post_test()

    def teardown(self):
        '''
        Called at the end of the fuzzing session, override with victim teardown
        '''
        self._stop_process()
        self._process = None
        super(MyController, self).teardown()

        
    def _stop_process(self):
        if self._is_victim_alive():

            ## execute the stop command
            self._process = Popen(self._server_stop_cmd, stdout=PIPE, stderr=PIPE)
            time.sleep(0.5)
        

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

# Define target and controller
target = TcpTarget(name='example_target', host='localhost', port=8088)
controller = MyController(name='ServerController',
        main_process_path="/usr/local/apache/bin/apachectl",
        server_start_cmd=["/usr/local/apache/bin/apachectl","start"],
        server_stop_cmd=["/usr/local/apache/bin/apachectl","stop"],
        process_args=[],
        process_env=None,
        logger=None)
target.set_controller(controller)

# Define model
model = GraphModel()

#model.connect(http_get_request_template)
#model.connect(http_get_request_template_1)
model.connect(http_get_request_template_2)

# Define fuzzer
fuzzer = ServerFuzzer()
fuzzer.set_interface(WebInterface(host='0.0.0.0', port=26000))
fuzzer.set_model(model)
fuzzer.set_target(target)
#fuzzer.set_delay_between_tests(0.2)
fuzzer.start()
print('-------------- done with fuzzing -----------------')
raw_input('press enter to exit')
fuzzer.stop()
