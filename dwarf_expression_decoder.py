"""
DWARF Expression Decoder
    Functions to decode DWARF expression as specfied in
    DWARF4 Spec - Section 2.5 'DWARF Expressions'

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

from elftools.dwarf.dwarf_expr import GenericExprVisitor, DW_OP_name2opcode
import logging
from register_map import RegisterMap

def decode_die_expression(die, attribute_name, address, registers,
                          address_space, frame_base):
    """Decode a expression that is found in a DIE attributes.
       The expression could be in location list(offset as DW_FORM_data)
       or embedded - this routine handles both.
    """
    dwarf_info = die.dwarfinfo
    if not die.attributes.has_key(attribute_name):
        return None
    attr = die.attributes[attribute_name]
    if attr.form.startswith('DW_FORM_data'):
        # The expression is in location list
        loc_lists = dwarf_info.location_lists()
        if loc_lists == None:
            logging.error('Not able to obtain Location List')
            return None
        # Get location list entry for the given address
        entry = loc_lists.get_location_list_entry(attr.value, address,
                                                  die.cu.get_low_pc())
        if entry == None:
            logging.error('Locaton List Entry not found')
            return None
        expr = entry.loc_expr
    else:
        # The expression is embedded
        expr = attr.value

    # Parse the expression and return result
    return parse_dwarf_expression(expr, dwarf_info, registers, address_space,
                                  frame_base)

def get_function_frame_base(frame, address_space):
    """ Convenience function to decode frame base of a function
    """
    return decode_die_expression(frame.fn_die, 'DW_AT_frame_base',
                                 frame.ip, frame.registers, address_space, None)

def parse_dwarf_expression(expression, dwarf_info, registers, address_space, 
                           frame_base):
    """ Parse the dwarf expression and returns the result.
    """
    #TODO - Replace the hardcoded x86-65
    register_map = RegisterMap('x86-64')
    if registers:
        reg_tab = registers.copy()
    else:
        reg_tab = None
    if frame_base:
        reg_tab[register_map.get_frame_pointer_register_number()] = frame_base
    decoder = ExpressionDecoder(dwarf_info.structs, address_space, reg_tab, frame_base)
    decoder.process_expr(expression)

    return decoder.get_result()

class ExpressionDecoder(GenericExprVisitor):
    """DWARF Expression decoder
        
       DWARF Expression decoder is a state machine operating on stack.
       The expression is byte stream. (Multiple operation is possible)
       The first byte is opcode followed by optional operands.
       The opcode determines the number of operands and their size.

       Most opcode performs some operation on the operand and pushes the result
       in the stack. When all the opcodes are parsed and end of byte stream is
       reached the last entry in the stack is result of the expression.

       For more info refer DWARF4 Spec - Section 2.5
    """
    def __init__(self, structs, address_space, registers, frame_base):
        super(ExpressionDecoder, self).__init__(structs)
        self.address_space = address_space
        self.registers = registers
        self.describe = ''
        self.stack = [0]
        #TODO - Replace this with proper value read from dwarfinfo
        self.default_data_size = 8
        self.frame_base = frame_base

    def _push(self, value):
        """ Push a value into stack
        """
        self.stack.append(value)

    def _pop(self):
        """ Pop last entry from the stack
        """
        return self.stack.pop()

    def _peek(self):
        """ Reterive last entry from the stack without removing it
        """
        return self.stack[-1]

    def _pick(self, index):
        """ Reterive a entry from stack and push it in the top
        """
        val = self.stack[-index]
        self._push(val)

    def _push_register(self, register_no, index=0):
        """ Push a register into the stack
        """
        self._push(self.registers[register_no] + index)

    def _push_frame_register(self, index):
        """ Read a value from memory at (frame_base + index) and push it
        """
        address = self.frame_base + index
        value = self.address_space.read_int(address, 8)
        self._push(value)

    def _do_op_pop1(self, op):
        """ Pop top entry from stack and execute OP(top)
            and push result back into the stack
        """
        top = self._pop()
        result = op(top)
        self._push(result)

    def _do_op_pop2(self, op):
        """ Pop 2 entries from stack and execute OP(first, second)
            and push result back into the stack
        """
        first = self._pop()
        second = self._pop()
        result = op(first, second)
        self._push(result)

    def _after_visit(self, opcode, opcode_name, args):
        """ GenericExprVisitor() will call this function after parsing each
            opcode and operands.

            This function just push/pop the entries to/from stack based on
            stack.
        """
        if opcode_name == 'DW_OP_addr' or opcode_name.startswith('DW_OP_const'):
            self._push(args[0])
        elif opcode_name == 'DW_OP_deref':
            self._do_op_pop1(lambda top: self.address_space.read_int(top, self.default_data_size))
        elif opcode_name == 'DW_OP_deref_size':
            self._do_op_pop1(lambda top: self.address_space.read_int(top, args[0]))
        elif opcode_name == 'DW_OP_dup':
            top = self._peek()
            self.push(top)
        elif opcode_name == 'DW_OP_drop':
            self.pop()
        elif opcode_name == 'DW_OP_over':
            self._pick(-1)
        elif opcode_name == 'DW_OP_pick':
            self._pick[args[0]]
        elif opcode_name == 'DW_OP_swap':
            top = self._pop()
            self.stack.insert(len(self.stack - 1), top)
        elif opcode_name == 'DW_OP_rot':
            top = self._pop()
            self.stack.insert(len(self.stack - 2), top)
        elif opcode_name == 'DW_OP_abs':
            self._do_op_pop1(lambda top: abs(top))
        elif opcode_name == 'DW_OP_and':
            self._do_op_pop2(lambda first, second: second & first)
        elif opcode_name == 'DW_OP_div':
            self._do_op_pop2(lambda first, second: second / first)
        elif opcode_name == 'DW_OP_minus':
            self._do_op_pop2(lambda first, second: first - second)
        elif opcode_name == 'DW_OP_mod':
            self._do_op_pop2(lambda first, second: second % first)
        elif opcode_name == 'DW_OP_mul':
            self._do_op_pop2(lambda first, second: second * first)
        elif opcode_name == 'DW_OP_neg':
            self._do_op_pop1(lambda top: -top)
        elif opcode_name == 'DW_OP_not':
            self._do_op_pop1(lambda top: ~top)
        elif opcode_name == 'DW_OP_or':
            self._do_op_pop2(lambda first, second: first | second)
        elif opcode_name == 'DW_OP_plus':
            self._do_op_pop2(lambda first, second: first + second)
        elif opcode_name == 'DW_OP_plus_uconst':
            self._do_op_pop1(lambda top: top + args[0])
        elif opcode_name == 'DW_OP_shl':
            self._do_op_pop2(lambda first, second: second << first)
        elif opcode_name == 'DW_OP_shr':
            self._do_op_pop2(lambda first, second: second >> first)
        elif opcode_name == 'DW_OP_xor':
            self._do_op_pop2(lambda first, second: second ^ first)
        elif opcode_name == 'DW_OP_le':
            self._do_op_pop2(lambda first, second: second <= first)
        elif opcode_name == 'DW_OP_ge':
            self._do_op_pop2(lambda first, second: second >= first)
        elif opcode_name == 'DW_OP_eq':
            self._do_op_pop2(lambda first, second: second == first)
        elif opcode_name == 'DW_OP_lt':
            self._do_op_pop2(lambda first, second: second < first)
        elif opcode_name == 'DW_OP_gt':
            self._do_op_pop2(lambda first, second: second > first)
        elif opcode_name == 'DW_OP_ne':
            self._do_op_pop2(lambda first, second: second != first)
        elif opcode_name.startswith('DW_OP_lit'):
            self._push(args[0])
        elif opcode_name == 'DW_OP_regx':
            self._push_register(args[0])
        elif opcode_name.startswith('DW_OP_reg'):
            self._push_register(opcode - DW_OP_name2opcode['DW_OP_reg0'])
        elif opcode_name == 'DW_OP_bregx':
            self._push_register(args[0], args[1])
        elif opcode_name.startswith('DW_OP_breg'):
            self._push_register(opcode - DW_OP_name2opcode['DW_OP_breg0'], args[0])
        elif opcode_name == 'DW_OP_fbreg':
            self._push_frame_register(args[0])
        elif opcode_name == 'DW_OP_nop':
            pass
        else:
            logging.error('DWARF expression opcode {0} is not yet implemented'\
                          .format(opcode_name))

        self.describe += '{0} {1}'.format(opcode_name, args)

    def get_result(self):
        """ Get the result from the stack and return.
        """
        return self._peek()

