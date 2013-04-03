"""
debugger.py:
    Contains helper functions that are called mostly by command_line.py

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
from process_coredump import Process
from dwarf_expression_decoder import (get_function_frame_base,
                                      decode_die_expression)
from data_structures import PyCompileUnit

import shared

BYTE_MASK = [0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFF, 0xFFFFFFFFFFFF,
             0xFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]

def get_threads():
    """ Returns threads in the process being debugged
    """
    if not hasattr(get_threads, 'pt_info'):
        get_threads.pt_info = Process(shared.symbol_file, shared.core_file)
    if get_threads.pt_info:
        return get_threads.pt_info.get_threads()

def get_thread(index):
    """ Returns thread of given index
        Note - Index != thread_id
    """
    threads = get_threads()
    if index >= 0 and index < len(threads):
        return threads[index]

    logging.error("Invalid thread index")
    return threads[0]

def get_frame(thread_index, index):
    """ Returns call frame of given thread and given index
    """
    thread = get_thread(thread_index)
    if thread == None:
        return None

    frames = thread.get_frames()
    if index < len(frames):
        return frames[index]

def get_current_frame():
    """ Returns current frame
    """
    return get_frame(shared.current_thread_index, shared.current_frame_index)

def get_frame_args(frame):
    """Get Function Parameters and their location
    """
    if frame.fn_die is None:
        return None

    return _fill_die_value(frame,
                           frame.fn_die.iter_children_of_type_parameter())

def get_frame_locals(frame):
    """Get Function variables and their location
    """
    if frame.fn_die is None:
        return None

    return _fill_die_value(frame,
                           frame.fn_die.iter_children_of_type_variable())

def _fill_die_value(frame, die_list):
    """ Fill DIE(args, locals) values
    """
    frame_base = get_function_frame_base(frame, shared.address_space)
    pycu = PyCompileUnit(frame.compile_unit)
    result = []
    for die in die_list:
        pydie = pycu.get_pydie(die)
        value = decode_die_expression(die, 'DW_AT_location', frame.ip,
                                      frame.registers, shared.address_space,
                                      frame_base)
        # The value decoded is 8 byte regardless of the datatype.
        # So truncate the value based on data type
        if value:
            value &= BYTE_MASK[pydie.get_base_type().size - 1]
        pydie.value = value
        result.append(pydie)

    return result

