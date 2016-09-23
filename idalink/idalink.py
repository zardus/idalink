#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Andrew Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# Standard library imports
import logging
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import warnings

from rpyc import classic as rpyc_classic

# Local imports
from .memory import CachedIDAMemory, CachedIDAPermissions


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


def _ida_connect(host, port):
    link = rpyc_classic.connect(host, port)
    LOG.debug('Connected to %s:%d', host, port)

    idc = link.root.getmodule('idc')
    idaapi = link.root.getmodule('idaapi')
    idautils = link.root.getmodule('idautils')

    return link, idc, idaapi, idautils


def ida_spawn(filename, ida_path, port=18861, mode='oneshot',
              processor_type='metapc'):
    """
    Open IDA on the the file we want to analyse.
    """
    ida_progname = _which(ida_path)
    if ida_progname is None:
        raise IDALinkError('Could not find executable %s' % ida_path)

    ida_realpath = os.path.expanduser(ida_progname)
    file_realpath = os.path.realpath(os.path.expanduser(filename))
    server_script = os.path.join(MODULE_DIR, 'server.py')
    logfile = LOGFILE.format(port=port)

    LOG.info('Launching IDA (%s) on %s, listening on port %d, logging to %s',
             ida_realpath, file_realpath, port, logfile)

    # :note: On Linux, we run IDA through screen because otherwise its UI will
    #        hang.
    #        We also setup the environment for IDA.
    #        The other parameters are:
    #        -A     Automatic mode
    #        -S     Run a script (our server script)
    #        -L     Log all output to our logfile
    #        -p     Set the processor type

    if sys.platform.startswith('win'):
        ida_env_script = os.path.join(MODULE_DIR, 'support', 'ida_env.bat')
        command_prefix = None
    else:
        ida_env_script = os.path.join(MODULE_DIR, 'support', 'ida_env.sh')
        command_prefix = ['screen', '-S', 'idalink-%d' % port, '-d', '-m']

    if sys.platform == "darwin":
        # If we are running in a virtual environment, which we should, we need
        # to insert the python lib into the launched process in order for IDA 
        # to not default back to the Apple-installed python because of the use 
        # of paths in library identifiers on macOS.
        if "VIRTUAL_ENV" in os.environ:
            ida_env_script = os.path.join(MODULE_DIR, 'support', 'ida_macos_env.sh')

    command = [
        ida_env_script,
        ida_realpath,
        '-M',
        '-A',
        '-S%s %d %s' % (server_script, port, mode),
        '-L"%s"' % logfile,
        '-p%s' % processor_type,
        file_realpath,
    ]

    if command_prefix:
        command = command_prefix + command

    LOG.debug('IDA command is %s', ' '.join(command))
    return subprocess.call(command)


class IDALinkError(Exception):
    pass


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
    def __init__(self, link, idc, idaapi, idautils, filename=None,
                 pull_memory=True):
        self.filename = filename
        self.link = link
        self.idc = idc
        self.idaapi = idaapi
        self.idautils = idautils

        self.remote_idalink_module = link.root.getmodule('idalink')
        self.remote_link = self.remote_idalink_module.RemoteIDALink(filename)

        self._memory = None
        self.pull_memory = pull_memory
        self._permissions = None

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


class idalink(object):
    """
    Opens a file in IDA locally.
    """

    def __init__(self, filename, ida_path, retries=60, port=None,
                 pull_memory=True, processor_type='metapc'):
        if port is None:
            port = random.randint(40000, 49999)
        # TODO: check if port is in use

        self._link = None
        self._host = 'localhost'
        self._port = port
        self._filename = os.path.realpath(os.path.join(os.getcwd(), filename)) 
        self._retries = retries
        self._pull_memory = pull_memory

        ida_spawn(self._filename, ida_path, port, processor_type)

    def __enter__(self):
        for _ in range(self._retries):
            # TODO: detect IDA failure intelligently
            try:
                time.sleep(1)
                LOG.debug('Trying to connect to IDA at %s:%d', self._host,
                          self._port)
                self._link = IDALink(*_ida_connect(self._host, self._port),
                                     filename=self._filename,
                                     pull_memory=self._pull_memory)
                break
            except socket.error:
                LOG.debug('... failed. Retrying.')

        if self._link is None:
            raise IDALinkError(('Failed to connect to IDA on port {} for '
                                'file {}').format(self._port, self._filename))

        return self._link

    def __exit__(self, type_, value, traceback):
        try:
            if self._link:
                self._link.idc.Exit(0)
        except EOFError:
            LOG.warning('EOF on link socket, IDA might still be running!')

    @property
    def link(self):
        """
        Helper property to support the use of idalink without having to use a
        with statement. This property will likely be deprecated and might be
        removed at any point in the future.
        """
        warnings.warn('link property is pending deprecation',
                      PendingDeprecationWarning)
        if self._link is None:
            self.__enter__()
        return self._link


class remote_idalink(idalink):
    """
    Connects to a remote instance of IDA that is already running the idalink
    server (e.g. via ida_spawn on a remote machine).
    """

    def __init__(self, host, port, retries=60, pull_memory=True):
        self._link = None
        self._host = host
        self._port = port
        self._filename = None
        self._retries = retries
        self._pull_memory = pull_memory
