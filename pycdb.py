#!/usr/bin/env python

"""
Python C Debugger

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

from __future__ import print_function
import sys
from os import path
import logging
import IPython
import ConfigParser

from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import get_formatter_by_name

#Enable accessing pycdb from anywhere
#TODO - deal with hardcoded pyelftools dependency
_PycdbPath = path.dirname(path.realpath(__file__))
sys.path.extend([_PycdbPath,
                _PycdbPath + '/../pymsasid',
                _PycdbPath + '/../pyelftools'])
from elftools import *
from elftools.elf.elffile import ELFFile
from symbols import Symbols
from address_space import AddressSpace

import shared
import command_line

parser = None

def r(command):
    """ Convenience function to run commands in IPython
        In combination with automatic quoting(;) this functions reduces lot of
        typing.
        For example:
        1) Instead of typing r("backtrace") just type ;r backtrace
        2) r("info registers") -> ;r info register
    """
    try:
        args = parser.parse_args(command.split())
    except SystemExit:
        return
    run_command(args)

def run_command(args):
    """ Runs the given command and prints the result
    """
    assert shared.symbol_file != None
    try:
        result, lexer_name = args.func(args)
    except:
        logging.error("Unexpected error: %s", sys.exc_info()[0])
        raise
    
    if result == None or result == '':
        return

    if args.color_lexer:
        lexer_name = args.color_lexer

    if args.no_color == False and lexer_name and lexer_name != '':
        try:
            lexer = get_lexer_by_name(lexer_name, stripall=True)
            formatter = get_formatter_by_name(args.color_formatter)
        except:
            logging.error("Not able format output")
        else:
            result = highlight(result, lexer, formatter)

    print(result)

def parse_cfg_file(args):
    """ Parse configuration file and set/get options
    """
    CONFIG_FILE_NAME = '.pycdb'
    DEBUG_SECTION = 'debug'
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_FILE_NAME)
    if not config.has_section(DEBUG_SECTION):
        config.add_section(DEBUG_SECTION)

    #If symbol/core file is not provided read it from config file(.pycdb)
    try:
        if args.symbol_file == None:
            args.symbol_file = config.get(DEBUG_SECTION, 'symbol-file')
        if args.core_file == None:
            args.core_file = config.get(DEBUG_SECTION, 'core-file')
    except ConfigParser.NoOptionError:
        #Ignore the error because if the file doesnt exists(first time) then
        #there wont be any option set
        pass

    #update the configuration file
    config.set(DEBUG_SECTION, 'symbol-file', args.symbol_file)
    config.set(DEBUG_SECTION, 'core-file', args.core_file)
    with open(CONFIG_FILE_NAME, 'wb') as configfile:
        config.write(configfile)

def main():
    """ Parse command line arguments and call appropriate functions
    """
    global parser
    parser = command_line.create_commandline_parser()

    #logging.basicConfig(level=logging.DEBUG)

    args = parser.parse_args()
    parse_cfg_file(args)

    if args.symbol_file == None:
        logging.error('No symbol file')

    shared.symbol_file = ELFFile(open(args.symbol_file, 'rb'))
    shared.symbols = Symbols(shared.symbol_file)

    if args.core_file:
        shared.core_file = ELFFile(open(args.core_file, 'rb'))
        shared.address_space = AddressSpace(shared.core_file)

    run_command(args)
    if args.interactive:
        IPython.embed()

#------------------------------------------------------------------
main()

