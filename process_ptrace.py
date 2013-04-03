"""
Copyright (c) 2012-2013 VMware, Inc. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""Contains classes to represent Threads in the Process
"""

from frames import Frames
from symbols import Symbols
from address_space import AddressSpace
from pyptrace import ptrace_getregs, ptrace_attach
from elftools.common.utils import struct_parse
import shared

class ProcessPtrace():
    """ Represents all the Threads captured in a running process
    """
    def __init__(self, sym_file, pid):
        self.current_thread = 0
        self.sym_file = sym_file
        self.pid = long(pid)
        self.symbols = Symbols(self.sym_file)
        self.threads = list()
        self.load_address_diff = 0
        self.address_space = shared.address_space

        #Add thread's info to the thread list
        thread = Thread(thread_id=self.pid, process=self)
        self.threads.append(thread)

    def _get_load_address_diff(self):
        """Returns the difference between loaded address and linked address
        """
        if self.load_address_diff != 0:
            return self.load_address_diff

        proc_path = '/proc/{pid}/auxv'.format(pid=self.pid)
        proc_stream = open(proc_path, 'rb', 0) 
        offset = 0
        while True:
            auxv_entry = struct_parse(self.sym_file.structs.Elf_Auxinfo,
                                      proc_stream, stream_pos=offset)
            offset += self.sym_file.structs.Elf_Auxinfo.sizeof()
            if auxv_entry.a_type == 'AT_NULL':
                break
            if auxv_entry.a_type == 'AT_ENTRY':
                core_entry = auxv_entry.a_val
                break

        if core_entry != 0:
            self.load_address_diff = self.sym_file.header.e_entry - core_entry
        else:
            self.load_address_diff = 0

        return self.load_address_diff

    def set_current_thread(self, thread_id):
        """Sets the current thread 
        """
        self.current_thread = thread_id

    def get_threads(self):
        """Returns Threads in the process
        """
        return self.threads

class Thread():
    """Represents a single Thread
    """
    def __init__(self, thread_id, process):
        self.thread_id = thread_id
        self.pid = process.pid

        self.sym_file = process.sym_file
        self.symbols = process.symbols
        self.address_space = process.address_space
        self.load_address_diff = process._get_load_address_diff()

        self._frames = None

    def __str__(self):
        ret = "%d" % self.thread_id
        #if (self.prpsinfo):
        #    ret += " %s" % self.prpsinfo.desc.pr_fname
        return ret

    def get_frames(self):
        """ Returns call frame of the thread
        """
        self._frames = Frames(registers = self.get_registers(),
                              load_address_diff = self.load_address_diff,
                              sym_file = self.sym_file,
                              symbols = self.symbols,
                              address_space = self.address_space)

        return self._frames

    def get_registers(self):
        """Returns register state 
        """
        ptrace_attach(self.pid)
        ptrace_regs = ptrace_getregs(self.pid)
        class registers:
            def __init__(self, regs):
                for name, reg in enumerate(regs._fields_):
                    self.__dict__[reg[0]] = getattr(regs, reg[0])

        return registers(ptrace_regs)

