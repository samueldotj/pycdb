"""
command_line.py:
    Command line parsing module

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

import argparse
import debugger
import shared
import logging
import sys
from disassemble import Disassemble
from elftools.elf.segments import LoadSegment
from elftools.elf.note import NoteSegment
from data_structures import get_pydie
from register_map import RegisterMap

BACKTRACE_FORMAT =  '#{index:<2d} {ip:#018x} '\
                        'in {function} ({parameters}) '\
                        'at {filename}:{line}\n'
LIST_LINE_FORMAT = '{line_no:4} {symbol:2} {line}'

CONTEXT_LINE_COUNT = 20
DEC_NUMBER_WIDTH = 24
HEX_NUMBER_WIDTH = 18
BIN_NUMBER_WIDTH = 64

REG_PRINT_ORDER = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                   'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                   'rip', 'rflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs']

LEXER_NAME_C = 'c'
LEXER_NAME_ASM = 'nasm'

def lexer(lexer_name):
    """decorator command_*() functions
       This decorator returns Lexer name along with the functions's result
    """
    def decorator(target):
        def wrapper(*args, **kwargs):
            return target(*args, **kwargs), lexer_name
        return wrapper
    return decorator

@lexer(LEXER_NAME_ASM)
def command_diassemble(args):
    """ Disassemble the given function or address range
    """
    result = ''

    if shared.symbol_file == None:
        logging.error('Symbol file not found')
        return

    section = shared.symbol_file.get_section_by_name('.text')
    if section is None:
        logging.error('.text section not found')
        return

    code = section.data()
    pc = section.address
    disassembly = Disassemble(input_stream=code, pc=pc,
                              mode=shared.symbol_file.elfclass, 
                              output=sys.stdout)
    #TODO - Convert this to return output
    result = disassembly.output()

    return result

@lexer(LEXER_NAME_C)
def command_whatis(args):
    """ Returns the textual description type of given variable or data structure
    """
    result = ''
    for pydie in get_pydie(args.datatype):
        result += '{0}:{1}:\n{2}\n'.format(pydie.file_name,
                                           pydie.line_number, pydie)

    return result

@lexer(None)
def command_info_thread(args):
    """ Returns all the threads in the process
    """
    threads = debugger.get_threads()
    result =    'Total thread contexts : {0}\n'\
                '  Id   Target Id         Frame\n'.format(len(threads))
    for index, thread in enumerate(threads):
        frames = thread.get_frames()
        frame = None
        if frames:
            frame = frames[0]
            frame.populate()
        result += '{active} {index:<4} {thread:<16}  {frame}\n'.format(
                    active='*' if index == shared.current_thread_index else ' ',
                    index=index, thread=thread, frame=frame)
    return result

@lexer(None)
def command_info_args(args):
    """ Returns information about the arguments in the frame
    """
    frame = debugger.get_current_frame()
    args = debugger.get_frame_args(frame)
    if args == None:
        return

    return '\n'.join('{arg.name} = {arg.value}'.format(arg=a) for a in args)

@lexer(None)
def command_info_locals(args):
    """ Returns information about local variable
    """
    frame = debugger.get_current_frame()
    args = debugger.get_frame_locals(frame)
    if args == None:
        return

    return '\n'.join('{arg.name} = {arg.value}'.format(arg=a) for a in args)

@lexer(None)
def command_info_core(args):
    """ Returns information about the core file
    """
    if shared.core_file == None:
        logging.warning('No core file specified')
        return
    
    note_seg = ''
    load_seg = '{0:{w}} {1:{w}} {2:{w}}\n'.format('Start', 'End', 'Size',
                                                  w=HEX_NUMBER_WIDTH)
    for segment in shared.core_file.iter_segments():
        if isinstance(segment, LoadSegment):
            start = segment.va_start
            end = segment.va_end
            load_seg += '{0:#0{w}x} {1:#0{w}x} {2:#0{w}x}\n'\
                        .format(start, end, end - start,
                                w=HEX_NUMBER_WIDTH)
        elif isinstance(segment, NoteSegment):
            for note in segment.notes:
                note_str = str(note)
                if note_str and note_str != '':
                    note_seg += '{0}\n'.format(note) 
    return note_seg + load_seg

@lexer(None)
def command_info_frame(args):
    """ Returns information about the frame
    """
    frame = debugger.get_current_frame()
    frame.populate()
    return str(frame)

@lexer(LEXER_NAME_ASM)
def command_info_registers(args):
    """ Returns registers in the current frame
    """
    frame = debugger.get_current_frame()
    reg_order = args.registers if args.registers else REG_PRINT_ORDER

    #TODO - Create architecture specific register map here
    register_map = RegisterMap('x86-64')

    result = ''
    for reg in reg_order:
        result += '{0:8} {1:#{w1}x} {1:{w2}} {1:#{w3}b}\n'\
                  .format(reg, frame.registers[register_map[reg]],
                          w1=HEX_NUMBER_WIDTH,
                          w2=DEC_NUMBER_WIDTH,
                          w3=BIN_NUMBER_WIDTH)
    return result

@lexer(None)
def command_backtrace(args):
    """ Returns stack trace for current thread
    """
    thread = debugger.get_thread(shared.current_thread_index)
    if thread is None:
        logging.error('Invalid thread {0}'.format(shared.current_thread_index))
        return

    frames = thread.get_frames()
    if len(frames) == 0:
        logging.warn('No frame to display')

    btf = BACKTRACE_FORMAT
    result = ''
    for index, frame in enumerate(frames):
        frame.populate()
        args = debugger.get_frame_args(frame)
        args_str = ', '.join('{arg.name} = {arg.value}'\
                    .format(arg=arg) for arg in args) if args else ''
        result += btf.format(index=index, ip=frame.ip, sp=frame.sp,
                             filename=frame.filename, line=frame.line,
                             function=frame.function, offset=frame.offset,
                             parameters=args_str)
    return result

@lexer(LEXER_NAME_C)
def command_list(args):
    """ Source code listing
    """
    ip = None
    if args.function:
        ip = shared.symbols.find_address(args.function)
    else:
        frame = debugger.get_current_frame()
        if frame == None:
            return
        ip = frame.ip

    addr2line = shared.symbols.addr2line(ip)
    if addr2line == None:
        logging.error('Not able to find source file')
        return
    file_path = addr2line.compilation_dir + '/' + addr2line.dir + '/' + \
                addr2line.file

    start_line = addr2line.line - (CONTEXT_LINE_COUNT / 2)
    if start_line < 0:
        start_line = 0
    end_line = start_line + CONTEXT_LINE_COUNT

    try: 
        source_file = open(file_path, 'r')
        lines = source_file.readlines()[start_line:end_line]
        source_file.close()
    except IOError:
        logging.error('Unable to read {0}'.format(file_path))
        return

    cur_line = 0
    while cur_line < CONTEXT_LINE_COUNT and cur_line < len(lines):
        line_no = start_line + cur_line
        symbol = '>>' if line_no == addr2line.line else ''
        lines[cur_line] = LIST_LINE_FORMAT.format(line_no=line_no,
                                                  symbol=symbol,
                                                  line=lines[cur_line])
        cur_line += 1

    return '{0}:{1}:\n{2}'.format(file_path, addr2line.line, ''.join(lines))

@lexer(None)
def command_examine(args):
    """Returns memory content
    """
    result = ''

    aspace = shared.address_space
    if aspace == None:
        logging.warning('Address space not created')
        return

    start_address = long(args.address, 0)
    if args.unit_size:
        unit_size = dict(b=1, h=2, w=4, g=8)[args.unit_size]
    else:
        unit_size = 4

    format_string = 'd'
    if args.format:
        units_per_row = 4
        format_string = args.format
        if args.format == 'x':
            format_string = '#0{0}x'.format(HEX_NUMBER_WIDTH)
    else:
        units_per_row = 4

    end_address = start_address + (args.repeat * unit_size)
    while start_address < end_address:
        result += '{0:#0{w}x}: '.format(start_address, w=HEX_NUMBER_WIDTH)
        for i in range(0, units_per_row):
            value = aspace.read_int(start_address + (i * unit_size), unit_size)
            result += '{0:{f}} '.format(value, f=format_string)
        result += '\n'
        start_address += (units_per_row * unit_size)

    return result

@lexer(None)
def command_thread(args):
    """Selects the current thread
    """
    shared.current_thread_index = args.thread_index

@lexer(None)
def command_frame(args):
    """Selects the current frame
    """
    shared.current_frame_index = args.frame_index
 
def create_commandline_parser():
    """Create command line parser
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--core-file', help='Core file to be debugged')
    parser.add_argument('-s', '--symbol-file', help='Symbol file')

    parser.add_argument('-cl', '--color-lexer', help='lexer name(c, as..)')
    parser.add_argument('-cf', '--color-formatter', default='console',
                        help='Formatter name(console, html, latex..)')
    parser.add_argument('-nc', '--no-color', action='store_true',
                        default=False,
                        help='Disable color output')
    parser.add_argument('-i', '--interactive', action='store_true',
                        default=False,
                        help='Land in interactive command prompt')

    parser.add_argument('-v', '--verbose', action='count', default=0)

    #disassemble
    subparsers = parser.add_subparsers()
    pa_dis = subparsers.add_parser('disassemble',
                                   help='Dissassemble a function or range')
    pa_dis.add_argument('-f', '--function', help='Disassemble given function')
    pa_dis.add_argument('-s', '--start', type=int, help='Start address')
    pa_dis.add_argument('-e', '--end', type=int, help='End address')
    pa_dis.set_defaults(func=command_diassemble)

    #thread
    pa_thread = subparsers.add_parser('thread', help='Sets the current thread')
    pa_thread.add_argument('thread_index', type=int, help='Thread index')
    pa_thread.set_defaults(func=command_thread)

    #frame
    pa_frame = subparsers.add_parser('frame', help='Sets the current frame')
    pa_frame.add_argument('frame_index', type=int, help='Frame index')
    pa_frame.set_defaults(func=command_frame)

    #whatis
    pa_what = subparsers.add_parser('whatis', help='Print datastructure type')
    pa_what.add_argument('datatype', help='Datatype or variable')
    pa_what.set_defaults(func=command_whatis)

    #info
    pa_info = subparsers.add_parser('info', help='Information about thread, '\
                                                  'frame, locals, args...')
    info_subpa = pa_info.add_subparsers()
    
    pa_info_thread = info_subpa.add_parser('threads', help='List all threads')
    pa_info_thread.set_defaults(func=command_info_thread)

    pa_info_locals = info_subpa.add_parser('locals', help='Print local'\
                                                          'variables')
    pa_info_locals.set_defaults(func=command_info_locals)

    pa_info_frame = info_subpa.add_parser('frame', help='Print frame info')
    pa_info_frame.set_defaults(func=command_info_frame)

    pa_info_args = info_subpa.add_parser('args',
                                         help='Print function arguments')
    pa_info_args.set_defaults(func=command_info_args)

    pa_info_reg = info_subpa.add_parser('registers', help='Print registers')
    pa_info_reg.add_argument('registers', nargs='*', help='Registers to print')
    pa_info_reg.set_defaults(func=command_info_registers)

    pa_info_core = info_subpa.add_parser('core', help='Info about core file')
    pa_info_core.set_defaults(func=command_info_core)

    #Backtrace
    pa_bt = subparsers.add_parser('backtrace', help='Print backtrace of '\
                                                     'current thread')
    pa_bt.set_defaults(func=command_backtrace)

    #list
    pa_ls = subparsers.add_parser('list', help='List source code')
    pa_ls.add_argument('function', nargs='?', default='',
                       help='Function to be listed')
    pa_ls.set_defaults(func=command_list)

    #examine - the popular 'x' command
    pa_x = subparsers.add_parser('examine', help='Examine memory content')
    pa_x.add_argument('address', help='Starting memory address to examine')
    pa_x.add_argument('-n', '--repeat', type=int, default=1,
                      help='How much memory to display')
    pa_x.add_argument('-f', '--format', choices='xduobacfsi',
                      help='Display format')
    pa_x.add_argument('-u', '--unit-size', choices='bhwg',
                      help='Unit size')
    pa_x.set_defaults(func=command_examine)

    return parser


