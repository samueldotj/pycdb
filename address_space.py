"""
address_space.py:
  Contains classes to represent the address space of the process
  that being debugged. It could be a core dump or live process.

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

from elftools.elf.segments import LoadSegment
from elftools.construct import Struct

""" AddressSpace - Represents address space of an application/coredump
    Only read operation is supported
"""
class AddressSpace:
    def __init__(self, core_file):
        """Creates an address space from the given core file
           Load and cache all the LoadSegments found on the core file
           TODO - This should be modified to include live debugging also
        """
        self.core_file = core_file
        self.load_segments = list()
        for segment in core_file.iter_segments():
            if isinstance(segment, LoadSegment):
                self.load_segments.append(segment)

    def read(self, address, size):
        """Returns one or more bytes(size) at the given address
           Can throw exception
        """
        for seg in self.load_segments:
            if address >= seg.va_start and address <= seg.va_end:
                offset = seg.file_offset + address - seg.va_start
                self.core_file.stream.seek(offset, 0)
                return self.core_file.stream.read(size)
        return None

    def read_int(self, address, size):
        """Wrapper function for read_intXX()
        """
        if size == 8:
            return self.read_int64(address)
        elif size == 4:
            return self.read_int32(address)
        elif size == 2:
            return self.read_int16(address)
        elif size == 1:
            return self.read_int8(address)

        raise ValueError

    def read_int64(self, address):
        """Returns 64bit at the given address
        """
        int64 = Struct("int", self.core_file.structs.Elf_word64("value"))
        return int64.parse(self.read(address, int64.sizeof())).value

    def read_int32(self, address):
        """Returns 32bit at the given address
        """
        int32 = Struct("int", self.core_file.structs.Elf_word("value"))
        return int32.parse(self.read(address, int32.sizeof())).value

    def read_int16(self, address):
        """Returns 16bit at the given address
        """
        int16 = Struct("int", self.core_file.structs.Elf_half("value"))
        return int16.parse(self.read(address, int16.sizeof())).value

    def read_int8(self, address):
        """Returns 8bit at the given address
        """
        int8 = Struct("int", self.core_file.structs.Elf_byte("value"))
        return int8.parse(self.read(address, int8.sizeof())).value


