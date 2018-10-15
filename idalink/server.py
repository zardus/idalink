# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Audrey Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao

from __future__ import print_function

# idc is just within IDA, so make pylint stop complaining
import idc      # pylint: disable=F0401
import threading

from rpyc.core import SlaveService
from rpyc.utils.server import OneShotServer, ThreadedServer

def main_thread(port):
    srv = ThreadedServer(SlaveService, port=port)
    srv.start()

def main():
    port = int(idc.ARGV[1]) if idc.ARGV[1:] else 18861
    thread_mode = idc.ARGV[2] == 'threaded' if idc.ARGV[2:] else False

    print('Received arguments: port=%s, thread_mode=%s' % (port, thread_mode))

    # :note: For speed, we don't want to idc.Wait() here,
    #        but you might want to call it in your code
    #        to make sure that autoanalysis has finished.

    if thread_mode:
        thread = threading.Thread(target=main_thread, args=(port, thread_mode))
        thread.daemon = True
        thread.start()
    else:
        srv = OneShotServer(SlaveService, port=port)
        # OneShotServer is a LIE so we have to do some shit
        # this is copied from https://github.com/tomerfiliba/rpyc/blob/master/rpyc/utils/server.py
        # specifically, the start method. if stuff breaks look here!
        srv._listen()
        srv._register()
        srv.accept()
        idc.Exit(0)

if __name__ == '__main__':
    main()
