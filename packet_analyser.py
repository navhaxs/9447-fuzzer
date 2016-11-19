#!/usr/bin/env python

import sys
import os
import threading
import Queue
import pyshark


class Packet_analyser:
    '''
    Packet_analyser runs on a separate thread to the main fuzzy.py
    It analyses pcap files for relevant http response codes
    and produces a report when it discovers interesting responses
    ''' 
    
    _queue = None
    _max_threads = 0
    _workers = []
    _error_codes = []

    def __init__(self, max_threads=4):
        self._queue = Queue.Queue()
        self._max_threads = max_threads
        for i in range(_max_treads):
            t = Thread(target = analyse_packet)
            t.daemon = True
            self._workers[i] = t
            t.start()

    def push_item(self, to_do ):
        # to_do is a tuple containing the session id and the test number
        _queue.put(to_do)
    
    def analyse_packet(self):
        while True:
            available = self._queue.get()
            session = available[0]
            test_number = available[1]
            filename = './pcaps/'+ str(session) + '/test_' + str(test_number) + '.pcap'
            cap = None

            try:
                cap = pyshark.FileCapture(filename, display_filter='http', only_summaries = True) 
            except:
                print 'File not found: ' + filename

            if cap != None:
                found = False
                for c in cap:
                    # look for error codes in the summaries
                    for error in self._error_codes:
                        if error.lower() in str(c).lower():
                            found = True
                            break
                    if found:
                        break
                
                if found:
                    # print summary, test number, session number
                    report_name = './pcaps/' + str(session) + '/' + str(session) + '_report_' + str(test_number)
                    
                        try:
                            r = open(report_name, 'w')
                            print r 'Session: ' + str(session)
                            print r 'Test Number: ' + str(test_number)
                            print r 'Error: ' + error
                            print r 'Summary: '
                            print r c
                        except:
                            print 'Could not open ' + report_name

            self._queue.task_done()

    def exit(self):
        '''
        Exit once all tasks in queue are complete
        _queue.join() will block until all tasks are complete
        '''
        self._queue.join()
