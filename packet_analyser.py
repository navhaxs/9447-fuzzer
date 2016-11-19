#!/usr/bin/env python

import sys
import os
import threading
import Queue


class Packet_analyser:
    _queue = None

    def __init__(self):
        _queue = Queue.Queue()

    def push_item(self, to_do ):
        # to_do is a tuple containing the session id and the test number
        _queue.put(to_do)
