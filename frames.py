"""
frame.py
    Contains classes to represent a call frame and collection of frames.

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

import logging
from elftools.dwarf.callframe import RegisterRule, CFARule
from data_structures import PyCompileUnit
from register_map import RegisterMap

class Frames():
    """ Creates call Frames for a given register set
        It does that by unwinding the stack(start from registers->RIP, RS).
    """
    def __init__(self, sym_file, load_address_diff, symbols,
                 registers, address_space):
        self.sym_file = sym_file
        self.load_address_diff = load_address_diff
        self.registers = registers
        self.symbols = symbols
        self.address_space = address_space
        self._frames = None
        self.dwarfinfo = self.sym_file.get_dwarf_info()

        #Log a warning if there is no debug_info section or debug_frame section
        if self.dwarfinfo == None:
            logging.warning('No debug info present in the file')
            return
        if not self.dwarfinfo.has_CFI():
            logging.warning('No CFI section')
            return

    def get_frames(self):
        """ Frames as list
        """
        if self._frames == None:
            self.build_frames()

        return self._frames

    def build_frames(self):
        """Build frames by X86-64 specific CFI or stack walk
        """

        registers = self.registers
        if registers == None:
            logging.warn('No register information')
            return

        register_map = RegisterMap('x86-64')
        ra_reg = register_map.get_ra_register_number()
        sp_reg = register_map.get_sp_register_number()

        reg_tab = register_map.create_register_table(registers)

        self._frames = list()
        stack_walk = True
        while True:
            reg_tab[ra_reg] +=  self.load_address_diff
            self._frames.append(Frame(reg_tab.copy(), register_map,
                                      self.sym_file, self.symbols))
            decoded_reg_tab = self._get_decoded_reg_tab(reg_tab, register_map)
            if decoded_reg_tab != None:
                reg_tab = decoded_reg_tab
                #We got a CFI so no need for further stack walking
                stack_walk = False
            if stack_walk:
                #Try stack walking (x86) if no CFI is not obtained so far
                reg_tab = self._stack_walk(reg_tab, register_map)
                if reg_tab == None:
                    break

            if decoded_reg_tab == None and stack_walk == False:
                #Both CFI and stack walk not possible
                logging.info('No CFI or stack walk possible further')
                break

            if reg_tab[ra_reg] <= 0L or reg_tab['pc'] <= 0L:
                logging.debug('Invalid PC encountered')
                break

            reg_tab[sp_reg] = reg_tab['cfa']

    def _stack_walk(self, reg_tab, register_map):
        """x86-64 specific stack walk
        """
        logging.info('Stack walking')
        ra_reg = register_map.get_ra_register_number()
        fp_reg = register_map.get_frame_pointer_register_number()
        rbp = reg_tab[fp_reg]
        try:
            ra = self.address_space.read_int64(rbp + 8)
            new_rbp = self.address_space.read_int64(rbp)
        except:
            logging.debug('Exception while trying to walk stack')
            return None

        if ra <= 0 or rbp <= 0 or new_rbp < rbp:
            logging.debug('Stack walk failed')
            return None

        reg_tab[ra_reg] = ra
        reg_tab[fp_reg] = new_rbp

        return reg_tab
       
    def _get_decoded_reg_tab(self, reg_tab, register_map):
        """Decode the register table for the given instruction pointer
        """
        ip = reg_tab[register_map.get_ra_register_number()]
        fde = self.dwarfinfo.CFI_entry(ip)
        if fde == None:
            logging.info('No CFI entry for ip {ip:#x}'.format(ip=ip))
            return None

        # Get decoded CFI entries for the given IP
        fde_decoded = fde.get_decoded()

        # walk through decoded rule table to find rule for the given ip
        for index, rule in enumerate(fde_decoded):
            #A single rule can be applicable to multiple consecutive IPs
            
            #start_ip - Rule's starting IP
            start_ip = rule['pc']
            #end_ip - Next rule's starting IP or last rule's IP
            if index < len(fde_decoded) - 1:
                end_ip = fde_decoded[index + 1]['pc'] - 1
            else:
                end_ip = fde['initial_location'] + fde['address_range']

            logging.debug('CFI rule ip {ip:#x} {start:#x} {end:#x}'\
                          .format(ip=ip, start=start_ip, end=end_ip))

            #skip the rule if IP is not within the range
            if ip >= start_ip and ip <= end_ip:
                # decode the registers
                for reg in rule:
                    reg_tab[reg] = self._decode_reg(rule[reg], reg_tab)

                reg_tab['pc'] = ip

                return reg_tab

        #No matching rule found
        logging.warning('No matching CFI rule found for {0:#x}'.format(ip))

    def _decode_reg(self, reg_rule, reg_tab):
        """ Decodes the cfi rule and updates the reg_tab with values for 
            corresponding registers
        """
        value = 0
        #register rule
        if type(reg_rule) is RegisterRule:
            if reg_rule.type == RegisterRule.OFFSET:
                address = reg_tab['cfa'] + reg_rule.arg
                value = self.address_space.read_int64(address)
            elif reg_rule.type == RegisterRule.VAL_OFFSET:
                value = reg_tab['cfa'] + reg_rule.arg
            elif reg_rule.type == RegisterRule.REGISTER:
                value = reg_tab[reg_rule.arg]
            elif reg_rule.type == RegisterRule.EXPRESSION:
                address = reg_tab[reg_rule.arg]
                value = self.address_space.read_int64(address)
            elif reg_rule.type == RegisterRule.VAL_EXPRESSION:
                value = reg_tab[reg_rule.arg]
        #cfa rule
        elif type(reg_rule) is CFARule:
            if reg_rule.reg:
                value = reg_tab[reg_rule.reg]
            if reg_rule.offset:
                value += reg_rule.offset
            if reg_rule.expr:
                value = reg_rule.expr
        else:
            value = reg_rule

        return value

    def __getitem__(self, key):
        return self.get_frames()[key]

    def __len__(self):
        return len(self.get_frames())

class Frame():
    """ A container class to hold IP, SP and registers
    """
    def __init__(self, registers, register_map, sym_file, symbols):
        self.registers = registers
        self.symbols = symbols
        self.sym_file = sym_file

        self._is_populated = False
        self.function = None
        self.offset = None
        self.filename = ''
        self.line = 0
        self.fn_die = None
        self.fn_pydie = None
        self.compile_unit = None

        ra_reg = register_map.get_ra_register_number()
        sp_reg = register_map.get_sp_register_number()

        self.ip = registers[ra_reg]
        self.sp = registers[sp_reg]
        self.line_program = self.line_entry = None
        logging.debug('Added ip {0:#x} sp {1:#x}'.format(self.ip, self.sp))

    def populate(self):
        """Populate the frame with additional informations
        """
        if self._is_populated:
            return

        if self.ip:
            self.function, self.offset = self.symbols.find_symbol(self.ip)

        dwarf_info = self.sym_file.get_dwarf_info()
        self.compile_unit = dwarf_info.get_cu_for_address(self.ip)
        self.fn_die = None
        self.line_program = None
        if self.compile_unit:
            self.line_program = dwarf_info.line_program_for_CU(self.compile_unit)
            self.line_entry = self.line_program.get_entry(self.ip)
            if self.line_entry and self.line_entry.state:
                self.filename = self.line_entry.state.get_file_name()
                self.line = self.line_entry.state.line
            else:
                #Top die contains the file name
                top_die = self.compile_unit.get_top_DIE()
                self.filename = top_die.attributes['DW_AT_name'].value
                self.line = 0

            self.fn_die = self.compile_unit.get_DIE_function(self.function)
            if self.fn_die:
                pycu = PyCompileUnit(self.compile_unit)
                self.fn_pydie = pycu.get_pydie(self.fn_die)

        self._is_populated = True

    def __str__(self):
        if self.ip and self._is_populated:
            return "{name}+{offset:#x}".format(name=self.function,
                                               offset=self.offset)
        else:
            return "ip:{ip:#x} sp:{sp:#x}".format(ip=self.ip, sp=self.sp)

