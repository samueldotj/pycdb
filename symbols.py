"""
symbols.py
    Functions that deal with symbol and addresses

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

import bisect
from collections import namedtuple
import logging
from os import path, access, R_OK

class Symbols():
    """Represents symbol section in the elf file
    """
    def __init__(self, sym_file):
        self.sym_file = sym_file
        self.symbol_sections = None

    def find_symbol(self, address, only_exact_match=False):
        """ Get the nearest symbol for the given address
            Returns the symbol name and offset difference
        """
        name = None
        offset = 0
        if self.sym_file == None:
            return name, offset

        """ Read symbol sections if not already done 
        """
        if self.symbol_sections == None:
            self.symbol_sections = self.sym_file.get_symbol_sections()

        """ Walk through all symbol sections
        """
        for section in self.symbol_sections:
            symbol_list = section.get_symbol_list()
            if symbol_list == None:
                continue

            """ The list is sorted - see the symbol section create class.
                So do a binary search to match
            """
            i = bisect.bisect_left(symbol_list, address)
            if i:
                sym = symbol_list[i-1]
                name = sym.name
                offset = address - sym.value

        if (only_exact_match and offset !=0 ):
            name = None

        return name, offset

    def find_address(self, name):
        """ Get the address for the given name
            Reverse of find_symbol()
        """

        """ Read symbol sections if not already done
        """
        if self.symbol_sections == None:
            self.symbol_sections = self.sym_file.get_symbol_sections()

        """ Walk through all symbol sections
        """
        for section in self.symbol_sections:
            symbol_dict = section.get_symbol_dict()
            if symbol_dict == None or not symbol_dict.has_key(name):
                continue
            return symbol_dict[name].value
        return None

    def _is_file_readable(self, file_path):
        return path.exists(file_path) and path.isfile(file_path) and\
            access(file_path, R_OK)

    def addr2line(self, ip):
        """ Returns filename and line for a given address
        """
        Addr2Line = namedtuple('Addr2Line', ['file', 'line', 'dir', 'compilation_dir'])
        dwarfinfo = self.sym_file.get_dwarf_info()
        compile_unit = dwarfinfo.get_cu_for_address(ip)
        if compile_unit == None:
            logging.warning('No compiliation unit for address {0:#x}'.format(ip))
            return
        line_program = compile_unit.get_line_program()
        if line_program == None:
            logging.warning('No line_program for address {0:#x}'.format(ip))
            return
        line_entry = line_program.get_entry(ip)
        if line_entry == None or line_entry.state == None:
            logging.warning('LineEntry not found for address {0:#x} trying '\
                            'next entry'.format(ip))
            line_entry = line_program.get_entry(ip, 1)
            logging.warning('No valid LineEntry found for address {0:#x}'\
                            .format(ip))
            return
        file_name = line_entry.state.get_file_name()
        line_number = line_entry.state.line
        compile_dir = compile_unit.get_compilation_directory()
        if not( path.exists(compile_dir) and path.isdir(compile_dir) and\
            access(compile_dir, R_OK)):
            compile_dir = '.'
        inc_directories = line_program.get_include_directory()
        for inc_dir in inc_directories:
            file_path = compile_dir + '/' + inc_dir + '/' + file_name
            if self._is_file_readable(file_path):
                return Addr2Line(file_name, line_number, inc_dir, compile_dir)
            else:
                logging.debug('Skipping {0}'.format(file_path))
        return Addr2Line(file_name, line_number, '', compile_dir)



