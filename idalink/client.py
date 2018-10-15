# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Audrey Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao

import logging
import os
import random
import socket
import subprocess
import sys
import tempfile
import time

from rpyc import classic as rpyc_classic

from .memory import CachedIDAMemory, CachedIDAPermissions
from .errors import IDALinkError


# Constants
LOG = logging.getLogger('idalink')
MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'support')
LOGFILE = os.path.join(tempfile.gettempdir(), 'idalink-{port}.log')


def _which(filename):
    if os.path.pathsep in filename:
        if os.path.exists(filename) and os.access(filename, os.X_OK):
            return filename
        return None
    path_entries = os.getenv('PATH').split(os.path.pathsep)
    for entry in path_entries:
        filepath = os.path.join(entry, filename)
        if os.path.exists(filepath) and os.access(filepath, os.X_OK):
            return filepath
    return None


def ida_connect(host='localhost', port=18861, retry=10):
    """
    Connect to an instance of IDA running our server.py.

    :param host:        The host to connect to
    :param port:        The port to connect to
    :param retry:       How many times to try after errors before giving up
    """
    for i in range(retry):
        try:
            LOG.debug('Connectint to %s:%d, try %d...', host, port, i + 1)
            link = rpyc_classic.connect(host, port)
            link.eval('2 + 2')
        except socket.error:
            time.sleep(1)
            continue
        else:
            LOG.debug('Connected to %s:%d', host, port)
            return link

    raise IDALinkError("Could not connect to %s:%d after %d tries" % (host, port, retry))


def ida_spawn(ida_binary, filename, port=18861, mode='oneshot',
              processor_type=None, logfile=None):
    """
    Open IDA on the the file we want to analyse.

    :param ida_binary:  The binary name or path to ida
    :param filename:    The filename to open in IDA
    :param port:        The port on which to serve rpc from ida
    :param mode:        The server mode. "oneshot" to close ida when the connection is closed, or
                        "threaded" to run IDA visible to the user and allow multiple connections
    :param processor_type:
                        Which processor IDA should analyze this binary as, e.g. "metapc". If not
                        provided, IDA will guess.
    :param logfile:     The file to log IDA's output to. Default /tmp/idalink-{port}.log
    """
    ida_progname = _which(ida_binary)
    if ida_progname is None:
        raise IDALinkError('Could not find executable %s' % ida_binary)

    if mode not in ('oneshot', 'threaded'):
        raise ValueError("Bad mode %s" % mode)

    if logfile is None:
        logfile = LOGFILE.format(port=port)

    ida_realpath = os.path.expanduser(ida_progname)
    file_realpath = os.path.realpath(os.path.expanduser(filename))
    server_script = os.path.join(MODULE_DIR, 'server.py')

    LOG.info('Launching IDA (%s) on %s, listening on port %d, logging to %s',
             ida_realpath, file_realpath, port, logfile)

    env = dict(os.environ)
    if mode == 'oneshot':
        env['TVHEADLESS'] = '1'

    if sys.platform == "darwin":
        # If we are running in a virtual environment, which we should, we need
        # to insert the python lib into the launched process in order for IDA
        # to not default back to the Apple-installed python because of the use
        # of paths in library identifiers on macOS.
        if "VIRTUAL_ENV" in os.environ:
            env['DYLD_INSERT_LIBRARIES'] = os.environ['VIRTUAL_ENV'] + '/.Python'

    # The parameters are:
    # -A     Automatic mode
    # -S     Run a script (our server script)
    # -L     Log all output to our logfile
    # -p     Set the processor type

    command = [
        ida_realpath,
        '-A',
        '-S%s %d %s' % (server_script, port, mode),
        '-L%s' % logfile,
    ]
    if processor_type is not None:
        command.append('-p%s' % processor_type)
    command.append(file_realpath)

    LOG.debug('IDA command is %s', ' '.join("%s" % s for s in command))
    return subprocess.Popen(command, env=env)


class RemoteIDALink(object):
    def __init__(self, filename):
        self.filename = filename
        self.link = None
        self.idc = __import__('idc')
        self.idaapi = __import__('idaapi')
        self.idautils = __import__('idautils')

        self.memory = CachedIDAMemory(self)
        self.permissions = CachedIDAPermissions(self)


class IDALink(object):
    """
    The main client object. Instanciating it will create a connection to some instance of IDA.

    There are two ways to use this class, either spawning a local copy of ida, or connecting to a
    remote instance of ida. For the former, provide `ida_binary` and `filename`. For the latter,
    provide `host` and `port`. The remote ida must have been spawned with the `ida_spawn` function.

    This object must be torn down to prevent the waste of system resources, either call `close`
    when you are finished or use it in a context manager. Kind of like a file object.

    :param str ida_binary:  The name of the ida executable to launch. If it does not contain a
                            slash it will be searched in $PATH.
    :param str filename:    The filename of the binary to analyze
    :param str host:        The hostname to connect to
    :param int port:        The port to connect to, or the port to spawn IDA listening on
    :param int retry:       How many times to retry the connection before giving up
    :param str processor_type:
                            The ida processor type to use, for example, "metapc". If not provided,
                            IDA will guess for you.
    :param str logfile:     The file to log IDA's output to, default ``/tmp/idalink-{port}.log``
    :param bool pull_memory:
                            Whether to eagerly load all of memory on the first memory access
    """
    def __init__(self,
            ida_binary=None,
            filename=None,
            host=None,
            port=None,
            retry=10,
            processor_type=None,
            logfile=None,
            pull_memory=True):

        if port is None:
            if host is not None:
                raise ValueError("Provided host but not port")
            port = random.randint(40000, 49999)

        if ida_binary is None and host is None:
            raise ValueError("Must provide ida_binary or host")
        if ida_binary is not None and host is not None:
            raise ValueError("Must provide exactly one of ida_binary and host")

        if ida_binary is not None:
            if filename is None:
                raise ValueError("Must provide filename if spawning a local process")

            self._proc = ida_spawn(ida_binary, filename, port, processor_type=processor_type, logfile=logfile)
            host = 'localhost'
        else:
            self._proc = None

        self._link = ida_connect(host, port, retry=retry)

        self.idc = self._link.root.getmodule('idc')
        self.idaapi = self._link.root.getmodule('idaapi')
        self.idautils = self._link.root.getmodule('idautils')

        self.remote_idalink_module = self._link.root.getmodule('idalink')
        self.remote_link = self.remote_idalink_module.RemoteIDALink(filename)

        self._memory = None
        self.pull_memory = pull_memory
        self._permissions = None
        self.filename = filename

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self._link.close()
        if self._proc is not None:
            self._proc.wait()

    @property
    def memory(self):
        if self._memory is None:
            self._memory = CachedIDAMemory(self)

            if self.pull_memory:
                self._memory.pull_defined()

        return self._memory

    @memory.deleter
    def memory(self):
        self._memory = None

    @property
    def permissions(self):
        if self._permissions is None:
            self._permissions = CachedIDAPermissions(self)
        return self._permissions

    @permissions.deleter
    def permissions(self):
        self._permissions = None
