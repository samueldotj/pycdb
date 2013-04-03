"""
This file contains classes to create new class at runtime to represent
C datastructures stored in the DWARF DIEs.

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

import bisect, string
import logging
from collections import OrderedDict, namedtuple
from elftools.dwarf.dwarf_expr import GenericExprVisitor
from dwarf_expression_decoder import decode_die_expression
import shared

def get_pydie(name):
    """Returns variable/structure/function with the given name 
    """
    for cu in shared.symbol_file.get_dwarf_info().iter_CUs():
        pycu = PyCompileUnit(cu)
        if pycu.die_hash.has_key(name):
            for pydie in pycu.die_hash[name]:
                yield pydie

class PyCompileUnit(object):
    """Represents a DWARF Compilation Unit and contains all the DIEs in the CU.
    """
    _instances = dict()
    def __new__(cls, *args, **kwargs):
        """ Restrict only one instance per compile unit
        """
        cu = args[0] 
        if cls._instances.has_key(cu):
            return cls._instances[cu]

        return super(PyCompileUnit, cls).__new__(cls, *args, **kwargs) 

    def __init__(self, cu):
        if PyCompileUnit._instances.has_key(cu):
            #Initialize only once
            return
        PyCompileUnit._instances[cu] = self

        self.compile_unit = cu

        """A dictionary of lists containing PyDie
            Key is PyDie name. A list is created even if there is no name
            collision(for simpilicity)
        """
        self.die_hash = dict()

        """A hash table to hold PyDie with offset as key
           This hash table is used to create parent/child link.
        """
        self.die_offset_hash = dict()

        self._parse_dies()

    def _parse_dies(self):
        """ Parse all the DIEs in the compilation unit(recursively)
        """
        self._parse_die_children(self.compile_unit.get_top_DIE())

    def _parse_die_children(self, die, parent=None):
        """ Create PyDie instacnes for children of given die
        """
        for child in die.iter_children():
            pydie = self._parse_pydie(child, parent)

    def _parse_pydie(self, die, parent=None):
        """Helper function to create PyDie from the given die
        """
        attr = die.attributes
        #if there is no attribute then return
        if attr == None or len(attr) == 0:
            return None 

        #get offset of first attribute
        offset = attr[attr.keys()[0]].offset
        #TODO - Remove after debugging
        assert not self.die_offset_hash.has_key(offset)

        if attr.has_key('DW_AT_type'):
            base_type_offset = attr['DW_AT_type'].value + 1
        else:
            base_type_offset = 0

        pydie = PyDie(die, self, base_type_offset, parent, offset)

        #Insert the pydie in the hash table
        if self.die_hash.has_key(pydie.name):
            collision_list = self.die_hash[pydie.name]
        else:
            collision_list = list()
        collision_list.append(pydie)
        self.die_hash[pydie.name] = collision_list

        self.die_offset_hash[offset] = pydie 

        #Parse children of this die
        self._parse_die_children(die, pydie)

        return pydie

    def get_pydie(self, die):
        """Return PyDie for the given die
        """
        attr = die.attributes
        offset = attr[attr.keys()[0]].offset
        if self.die_offset_hash.has_key(offset):
            return self.die_offset_hash[offset]

class PyDie():
    """This class represents a DWARF DIE
    """
    def __init__(self, die, pycu, base_type_offset=0, parent=None, offset=0):
        self.die = die
        self.pycu = pycu
        self.children = OrderedDict()
        self.base_type_offset = base_type_offset
        attr = die.attributes

        def get_attr_value(attr_name, default=0):
            if attr.has_key(attr_name):
                return attr[attr_name].value
            else:
                return default

        self.name = get_attr_value('DW_AT_name', '')
        self.size = get_attr_value('DW_AT_byte_size')
        self.encoding = get_attr_value('DW_AT_encoding') 
        self.upper_bound = get_attr_value('DW_AT_upper_bound')
        self.bit_size = get_attr_value('DW_AT_bit_size')
        self.bit_offset = get_attr_value('DW_AT_bit_offset')
        file_no = get_attr_value('DW_AT_decl_file')
        if file_no == 0:
            self.file_name = ''
        else:
            line_program = die.dwarfinfo.line_program_for_CU(die.cu)
            self.file_name = line_program.header.file_entry[file_no - 1].name
        self.line_number = get_attr_value('DW_AT_decl_line')
        self.offset = offset

        self.parent = parent

        self.byte_offset = 0
        if die.tag == 'DW_TAG_member' and\
           attr.has_key('DW_AT_data_member_location'):
            loc = LocExprDecoder(die.cu.structs)
            loc.process_expr(attr['DW_AT_data_member_location'].value)
            self.byte_offset = loc.byte_offset[0]

        if parent:
            parent.children[self.name] = self

        self._dso = None

    def get_base_type(self):
        """Returns base type die of the current die
        """
        if self.pycu.die_offset_hash.has_key(self.base_type_offset):
            return self.pycu.die_offset_hash[self.base_type_offset]
        return None

    def is_pointer(self):
        """Returns true if the datatype is of type pointer
        """
        return self.die.tag == 'DW_TAG_pointer_type'

    def is_pointer_ancestor(self):
        """Returns true if the datatype or any of the base type 
           is of type pointer
        """
        if self.is_pointer():
            return True
        base_type = self.get_base_type()
        if base_type:
            return base_type.is_pointer_ancestor()
        return False

    def is_struct(self):
        return self.die.tag == 'DW_TAG_structure_type'

    def is_typedef(self):
        return self.die.tag == 'DW_TAG_typedef'

    def is_union(self):
        return self.die.tag == 'DW_TAG_union_type'

    def is_container(self):
        return self.is_struct() or self.is_typedef() or self.is_union()

    def is_volatile(self):
        return self.die.tag == 'DW_TAG_volatile_type'

    def is_const(self):
        return self.die.tag == 'DW_TAG_const_type'

    def is_array(self):
        return self.die.tag == 'DW_TAG_array_type'

    def is_subprogram(self):
        return self.die.tag == 'DW_TAG_subprogram'

    def is_member(self):
        return self.die.tag == 'DW_TAG_member'

    def is_variable(self):
        return self.die.tag == 'DW_TAG_variable'

    def get_upper_bound(self):
        """Returns array size
        """
        base_type = self.get_base_type()
        if base_type and base_type.is_array():
            return base_type.children[''].upper_bound + 1
        return -1

    def set_upper_bound(self, count):
        """Sets the array size
        """
        base_type = self.get_base_type()
        if base_type and base_type.is_array():
            base_type.children[''].upper_bound = count

    def get_str(self, indent):
        """Returns pretty string describing the current datatype
        """
        base_type = self.get_base_type()
        type_name = ''

        if base_type:
            if self.is_pointer() and not base_type.is_pointer():
                return base_type.name + ' *' + self.name
            type_name = base_type.get_str(indent + 1)

        def _convert_tag(base_type_name):
            if self.is_typedef():
                result = ('typedef ' if indent == 0 else '') + base_type_name
            elif self.is_struct():
                result = 'struct ' 
            elif self.is_union():
                result = 'union'
            elif self.is_pointer():
                if self.get_base_type() is None:
                    result = 'void *'
                else:
                    result = base_type_name + '*'
            elif self.is_volatile():
                result = 'volatile ' + base_type_name
            elif self.is_const():
                result = 'const ' + base_type_name
            else:
                result = base_type_name

            return result.strip()

        result = _convert_tag(type_name)
        if not result.endswith('*'):
            result += ' '
        result += self.name

        if self.bit_offset != 0 or self.bit_size != 0:
            result += ':%d@%d' % (self.bit_size, self.bit_offset)

        if self.get_upper_bound() != -1:
            result += '[%d]' % self.get_upper_bound()

        def _get_fields():
            fields = ''
            for child in self.children:
                child_str = self.children[child].get_str(indent + 1)
                fields += "%s\t%s\n" % (''.ljust(indent, '\t'), child_str)
            return fields

        if not self.is_pointer_ancestor() and \
           (self.is_struct() or self.is_union()):
            fields = _get_fields()
            result += ' {\n %s%s}' % (fields, ''.ljust(indent - 1, '\t'))

        if self.is_member() or self.is_variable():
            result += ';'

        return string.expandtabs(result, 4)

    def get_dso(self):
        """ Returns Data Structure Object for the current PyDie
        """
        if self._dso:
            # Return cached copy if available    
            return self._dso

        base_dso = None
        base_type = self.get_base_type()
        while base_type and (base_type.is_const() or base_type.is_volatile()):
            base_type = base_type.get_base_type()

        if base_type and not base_type.is_pointer():
            base_dso = base_type.get_dso()

        self._dso = DataStructureObject(name=self.name, base_type=base_dso,
                                        byte_offset=self.byte_offset, pydie=self)
        return self._dso

    def __str__(self):
        return self.get_str(0)

    def _repr__(self):
        return self.__str__()


class LocExprDecoder(GenericExprVisitor):
    """DWARF Location Expression decoder
       This decoder expects only 'DW_OP_plus_uconst'.
       It is ok since inside a structure we dont expect anything else
    """
    def __init__(self, structs):
        super(LocExprDecoder, self).__init__(structs)
        self.byte_offset = 0

    def _after_visit(self, opcode, opcode_name, args):
        if opcode_name == 'DW_OP_plus_uconst':
            self.byte_offset = args
        else:
            logging.error('Dont know how to process opcode {0}({1})'\
                          .format(opcode_name, opcode))


class DataStructureObject():
    """This class makes all datatype available in DWARF as a python class.
       That is if a c file had structure like this
       typedef struct {
           int first;
           struct {
               int val[10];
           }second;
       }test;
       then this class allows inside python that structure can be accessed like

       print test.first
       print test.second.val[2]

       These members exists virtually - They are not regualar class members.
       see __getattr__() and __getitem__() for implementation details.
        
    """
    def __init__(self, name, base_type, byte_offset, pydie, address=None):
        assert pydie != None

        byte_size = pydie.size
        if byte_size == 0 and base_type:
            # If base type is available calculate the size of this DIE from it.
            byte_size = len(base_type)
            
        self._internal = _DsoInternal(name, base_type, byte_offset, byte_size,
                                      pydie, address)

    def _get_parent(self):
        """ Returns parent DSO if exists
        """
        internal = self._internal
        if internal.parent:
            return internal.parent
        ppydie = internal.pydie.parent
        if ppydie == None:
            return
        internal.parent = ppydie.get_dso()
        return internal.parent


    def _clone(self, parent_offset=0, address=0):
        """Create copy of the DSO.
           Cloning is needed to avoid modifying the same DSO in two places.
        """
        internal = self._internal
        dso = DataStructureObject(name=internal.name, base_type=internal.base_type,
                                  byte_offset=parent_offset + internal.byte_offset,
                                  pydie=internal.pydie, address=internal.memory_offset)
        dso_internal = dso._internal
        dso_internal.parent = self
        dso_internal.memory_offset = address
        return dso

    def _link_children(self, address):
        """Read all children and create link(dict)
        """
        internal = self._internal
        unique = 0
        for pydie in internal.pydie.children:
            dso = pydie.get_dso()
            dso = dso._clone(internal.byte_offset,
                             address + dso._internal.byte_offset)
            name = dso._internal.name
            """C allows anon union and structs but we cant do that (at
               least for now) so name them uniquely
            """
            if name.strip() == '':
                unique += 1
                name = '_%s' % unique

            internal.children[name] = dso
            if address == None:
                address = self.get_address(True)
            internal.parent = self

    def _get_member(self, item, address=None):
        """ Returns members inside the structure

            address - Address of the parent
        """
        internal = self._internal

        if not internal.children_linked:
            internal.children_linked = True
            self._link_children(address)

        if internal.children.has_key(item):
            member = internal.children[item]
            return member

        btype = internal.base_type
        if btype == None:
            return

        """ Ignore all pointers and locate the data type actually pointing
            ie in both the following cases we want to find my_struct_t
                my_struct_t *x;
                my_struct_t ******y; 
        """    
        while btype and btype._internal.pydie.is_pointer():
            btype = btype.base_type

        """ If the base type is container(structure, union or typedef) then
            try to access the member inside it
        """
        if btype and btype._internal.pydie.is_container():
            return btype._get_member(item, address + btype._internal.byte_offset)

    def __getattr__(self, item):
        """Make the child members inside accessible using dot notation
           For example - "dso.my_struct.field" is possible
        """
        #_internal contains metadata associated with the structure
        if item == "_internal":
            return object.__getattr__(self, item)

        assert isinstance(self, DataStructureObject)
        member = self._get_member(item, self.get_address(True))
        if member == None:
            raise AttributeError(item)
        return member

    def __getitem__(self, key):
        """ Override [] so that dso.my_struct.field[0] is allowed
        """
        internal = self._internal
        pydie = internal.pydie
        if key < 0 or key > pydie.get_upper_bound():
            raise IndexError

        offset = internal.base_type.sizeof() * key
        element = self._clone(offset)

        #Reset the upperbound since we are returning only one element
        element._internal.pydie.set_upper_bound(0)
        return element

    def sizeof(self):
        """Retuns size of the underlying data structure
        """
        return self._internal.byte_size

    def offsetof(self, member):
        """Returns offset of the given member from the structure
        """
        field = self._get_member(member)
        if field == None:
            raise AttributeError(member)
        return field._internal.byte_offset

    def __len__(self):
        """Alias for sizeof()
        """
        return self.sizeof()

    def __str__(self):
        return self._internal.name

    def __format__(self, format_spec):
        if isinstance(format_spec, unicode):
            return unicode(str(self))
        else:
            return str(self)

    def __cmp__(self, other):
        if other == None:
            return 1
        internal = self._internal
        if internal.value == None:
            return None == other
        return internal.value.__cmp__(other)

    def __eq__(self, other):
        if other == None:
            return False
        internal = self._internal
        if internal.value == None:
            return None == other
        return internal.value.__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __coerce__(self, other):
        internal = self._internal
        if internal.value == None:
            return None
        return internal.value.__coerce__(other)

    def __nonzero__(self):
        internal = self._internal
        if internal.value:
            return internal.value
        return True

    def value(self):
        """ Returns value of this DIE.
            This is done by reading from memory at offset address of this DIE
            The address is calculated from the DW_AT_Location attribute
        """
        internal = self._internal
        if internal.value:
            return internal.value

        address = self.get_address()
        if address == None:
            return

        internal.value = shared.address_space.read(address, len(self))

        return internal.value

    def get_address(self, dont_disturb_parent=False):
        """ Returns address of this DIE variable.
        """
        internal = self._internal
        if internal.memory_offset:
            #check cache first
            return internal.memory_offset
        elif internal.pydie.is_variable():
            #calculate the address from DIE location expression
            address = decode_die_expression(internal.pydie.die,
                                            'DW_AT_location', None,
                                            None, shared.address_space, None)
            internal.memory_offset = address
            return address

        #Try to visit parent and get address from there
        if dont_disturb_parent:
            return

        parent = self._get_parent()
        if parent == None:
            return

        #Recursively try to find a parent which has address
        parent_offset = parent.get_address()
        if parent_offset == None or parent_offset == 0:
            return

        return parent_offset + internal.byte_offset

    def set_address(self, address):
        """ Sets address of this variable
        """
        assert address
        internal = self._internal
        internal.memory_offset = address
        return internal.memory_offset

    def get_pydie(self):
        return self._internal.pydie

    def get_type_description(self, indent=0, offset=0):
        """Returns string representation(c format) of the DSO.
        """
        internal = self._internal
        btype = internal.base_type
        bpydie = btype._internal.pydie if btype else None
        name = internal.name
        byte_offset = internal.byte_offset
        if name.strip() == '':
            name = '<anon>'
        result = ''.ljust(indent, '\t')
        result += '%s' % name
        array_size = internal.pydie.get_upper_bound() 
        if array_size != -1:
            result += '[%d]' % (array_size)
        result += ' @ %d' % (offset + byte_offset)
        if internal.bit_size > 0:
            result += ':%d' % (internal.bit_offset)
            if internal.bit_size > 1:
                result += '-%d' % (internal.bit_offset + internal.bit_size)

        result += '\n'
        result = string.expandtabs(result, 4)
        indent += 1

        if bpydie:
            if bpydie.is_container():
                result += btype.get_type_description(indent, offset + byte_offset)
            else:
                logging.info('{0} is not coded yet '.format(bpydie.die.tag))
        else:
            for child in internal.children:
                result += child.get_type_description(indent, offset)
 
        return result

class _DsoInternal():
    """A class to hold meta data of DSO
    """
    def __init__(self, name, base_type, byte_offset, byte_size, pydie, address):
        self.name = name
        self.base_type = base_type
        self.byte_offset = byte_offset
        self.byte_size = byte_size
        self.pydie = pydie
        self.memory_offset = address

        self.bit_offset = pydie.bit_offset
        self.bit_size = pydie.bit_size

        self.value = None
        self.children = OrderedDict()
        self.children_linked = False
        self.parent = None

