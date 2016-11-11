#!/usr/bin/env python
import socket
import time
import traceback
import sys
import threading
import getopt
import argparse
from subprocess import *
from kitty.targets.server import ServerTarget
from kitty.model import *
from kitty.fuzzers import ServerFuzzer
from kitty.controllers.base import BaseController
# from katnip.controllers.client.process import MyController
from katnip.targets.tcp import TcpTarget
from kitty.interfaces import WebInterface
#from kitty.core.threading_utils import FuncThread

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
# Usage: specify files containing templates as arguments

################# Data Models #################

# Data models given in files specified in arguments
# Data models should be in the specified format, no checking of sanity of templates is done :)

"""
Template(name='HTTP_GET_TEMPLATE', fields=[
    String('GET', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])
"""



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

def fuzz(template='http_get_request_template_1', target_host='127.0.0.1', target_port=25000, cont_main_process_path='/usr/local/apache/bin/apachectl', web_interface_host='0.0.0.0', web_interface_port=26000):
    # Define target and controller
    target = TcpTarget(name='example_target', host=target_host, port=target_port)
    controller = MyController(name='ServerController',
            main_process_path=cont_main_process_path,
            server_start_cmd=[cont_main_process_path,"start"],
            server_stop_cmd=[cont_main_process_path,"stop"],
            process_args=[],
            process_env=None,
            logger=None)
    target.set_controller(controller)


    # Define model
    model = GraphModel()
    t = open(template, 'r')
    http_template = eval(t.read())
    model.connect(http_template)
    #model.connect(http_get_request_template)
    #model.connect(http_get_request_template_1)
    #model.connect(http_get_request_template_2)

    # Define fuzzer
    fuzzer = ServerFuzzer()
    fuzzer.set_interface(WebInterface(host=web_interface_host, port=web_interface_port))
    fuzzer.set_model(model)
    fuzzer.set_target(target)
    fuzzer.set_delay_between_tests(0.2)
    

    print('-------------- starting fuzzing -----------------')
    print('-------------- ' + template + ' -----------------')
    print('------ Web interface port ' + str(web_interface_port) + ' -------------- ')
    fuzzer.start()
    print('-------------- done with fuzzing -----------------')
    raw_input('press enter to exit')
    fuzzer.stop()


def usage():
    print('This is a server based fuzzer. In order to begin fuzzing, specify the main process path using the -m or --main option, followed by at least one file containing a http request template as specified by kitty.')
    print('Example usage: ./fuzzy.py -m \'/usr/local/apache/bin/apachectl\' http_get_request_template_1')
    print('-h, --help for this message')
    print('-m, --main for path to main process')


### main here ###
'''
if len(sys.argv) <= 1:
    usage()
    sys.exit(2)
else:
    
    try:
        opts, args = getopt.getopt(sys.argv, 'hm:', ['help', 'main='])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    
    if len(args) <= 0:
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-m', '--main'):
            main_process_path = arg
    '''

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--main', help='path to main process')
parser.add_argument('template', nargs='+', help='file containing a http request template as specified by kitty')
parser.add_argument('-p', '--port', type=int, help='server port')
args = parser.parse_args()

if args.main == None:
    print 'Error: Main process path not specified'
    sys.exit(2)
elif args.port == None:
    print 'Error: Server port not specified'
    sys.exit(2)


main_process_path = args.main
# we can change these based on options?
target_host = '127.0.0.1'
start_target_port = args.port
web_interface_host = '0.0.0.0'
start_web_interface_port = 26000

#print main_process_path
'''
for t in args.template:
    
    fuzz_args = {'template':t, 'target_host': target_host, 'target_port':start_target_port, 'cont_main_process_path': main_process_path, 'web_interface_host':web_interface_host, 'web_interface_port':start_web_interface_port}
    thread = threading.Thread(target=fuzz, kwargs = fuzz_args)
    start_target_port += 1
    start_web_interface_port += 1
    thread.start()
    

    #print t
'''

for t in args.template:
    fuzz(template = t, target_host = target_host, target_port = start_target_port, cont_main_process_path = main_process_path, web_interface_host = web_interface_host, web_interface_port = start_web_interface_port)
    start_target_port += 1
    start_web_interface_port += 1
