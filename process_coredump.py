"""
process_coredump.py
   Contains classes to represent Threads in the Process that is being
   debugged.


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

from elftools.elf.note import NoteSegment
from frames import Frames
from symbols import Symbols
from address_space import AddressSpace

class Process():
    """ Represents all the Threads captured in the CoreDump file
    """
    def __init__(self, sym_file, core_file):
        self.current_thread = 0
        self.sym_file = sym_file
        self.core_file = core_file
        self.symbols = Symbols(self.sym_file)
        self.threads = list()
        self.load_address_diff = 0
        self.address_space = AddressSpace(core_file)

        def get_next_note(start_index, n_type, end_type='NT_PRSTATUS'):
            """Search and find note of given type
            """
            note_index = start_index
            while note_index < len(segment.notes):
                note = segment.notes[note_index]
                if note.entry.n_type == end_type:
                    return None
                if note.entry.n_type == n_type:
                    return note
                note_index += 1

        def parse_notes(segment):
            """Parse notes in the core file and create thread object for each
                PRSTATUS, PRPSINFO and PRFPREG tuple
            """
            for note_index, note in enumerate(segment.notes):
                if note.entry.n_type != 'NT_PRSTATUS':
                    continue
                prstatus = note
                thread_id = prstatus.desc.pr_pid
                prpsinfo = get_next_note(note_index + 1, 'NT_PRPSINFO')
                fpregset = get_next_note(note_index + 1, 'NT_PRFPREG')
                #Add thread's info to the thread list
                thread = Thread(thread_id=thread_id, prpsinfo=prpsinfo,
                                prstatus=prstatus, fpregset=fpregset,
                                process=self)
                self.threads.append(thread)

        for segment in core_file.iter_segments():
            if not isinstance(segment, NoteSegment):
                continue
            parse_notes(segment)

    def _get_load_address_diff(self):
        """Returns the difference between loaded address and linked address
        """
        if self.load_address_diff != 0:
            return self.load_address_diff
        core_entry = 0
        for segment in self.core_file.iter_segments():
            if not isinstance(segment, NoteSegment):
                continue
            for note in segment.notes:
                if note.entry.n_type == 'NT_AUXV':
                    for aux in note.desc:
                        if aux.a_type == 'AT_ENTRY':
                            core_entry = aux.a_val
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
    def __init__(self, thread_id, prpsinfo, prstatus, fpregset, process):
        self.thread_id = thread_id
        self.prpsinfo = prpsinfo
        self.prstatus = prstatus
        self.fpregset = fpregset

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

    def _get_prstatus(self):
        return self.prstatus
    def _get_prpsinfo(self):
        return self.prpsinfo
    def _get_fpregset(self):
        return self.fpregset

    def get_frames(self):
        """ Returns call frame of the thread
        """
        if self._frames:
            return self._frames

        self._frames = Frames(registers = self.get_registers(),
                              load_address_diff = self.load_address_diff,
                              sym_file = self.sym_file,
                              symbols = self.symbols,
                              address_space = self.address_space)
        return self._frames

    def get_registers(self):
        """Returns register state 
        """
        if self.prstatus != None:
            return self.prstatus.desc.pr_reg.register
        else:
            return None

