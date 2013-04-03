"""
register_map.py:
    Map given register name to architecture specific index

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

class RegisterMap():
    def __init__(self, architecture):
        self.architecture = architecture

        _reg_map = None

        """Refer x86-64 ABI documentation for this mapping
        """
        if self.architecture:
            _reg_map = dict(RAX=0, RDX=1, RCX=2, RBX=3, RSI=4, RDI=5, RBP=6, 
                            RSP=7, R8=8, R9=9, R10=10, R11=11, R12=12, R13=13,
                            R14=14, R15=15, RA=16, XMM0=17, XMM1=18, XMM2=19,
                            XMM3=20, XMM4=21, XMM5=22, XMM6=23, XXM7=24,
                            XMM8=25, XMM9=26, XMM10=27, XMM11=28, XMM12=29,
                            XMM13=30, XMM14=31, XMM15=32, ST0=33, ST1=34,
                            ST2=35, ST3=36, ST4=37, ST5=38, ST6=39, ST7=40,
                            MM0=41, MM1=42, MM2=43, MM4=44, MM5=45, MM6=46,
                            MM7=47, MM8=48, RFLAGS=49, ES=50, CS=51, SS=52,
                            DS=53, FS=54, GS=56, FS_BASE=58, GS_BASE=59)
        self._reg_map = _reg_map

    def __getattr__(self, name):
        name = name.upper()
        #TODO - X86-64 specific registers are accessed here
        if name == 'RIP':
            name = 'RA'
        return self._reg_map[name]

    def __getitem__(self, item):
        return self.__getattr__(item)

    def create_register_table(self, registers):
        reg_tab = {}
        #copy members in the register class to dict
        for reg, value in registers.__dict__.iteritems():
            reg = reg.upper()
            if self._reg_map.has_key(reg):
                reg_tab[self._reg_map[reg]] = value

        #special registers
        reg_tab['cfa'] = registers.rsp
        #TODO - X86-64 specific registers are accessed here
        if self.architecture:
            reg_tab['pc'] = registers.rip
            reg_tab[self.RA] = registers.rip

        return reg_tab

    def get_ra_register_number(self):
        return self.RA

    def get_sp_register_number(self):
        return self.RSP

    def get_frame_pointer_register_number(self):
        if self.architecture:
            return self.RBP

