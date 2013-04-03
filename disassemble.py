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

""" Disassemble(x86) given stream
"""
import pymsasid
import syn_c

class Disassemble():
    """ Disassemble(x86) given stream
    """
    def __init__(self, input_stream='', pc=0, mode=64, output=None):
        """ input_stream:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.input = input_stream
        self.pc = pc
        self.mode = mode

    def set_code(self, input_stream, pc):
        self.input = input_stream
        self.pc = pc

    def output(self):
        result = ''
        pymsas = pymsasid.Pymsasid(source=self.input, hook=pymsasid.BufferHook,
                                   syntax=syn_c.c_syntax, vendor=pymsasid.VENDOR_AMD)
        pymsas.dis_mode = self.mode
        pymsas.pc = self.pc

        pos = 0
        while pos < len(self.input):
            inst = pymsas.decode()
            result += str(inst) + '\n'
            pos += inst.size

        return result

