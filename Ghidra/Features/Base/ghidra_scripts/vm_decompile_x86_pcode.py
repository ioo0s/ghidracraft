## ###
#  IP: GHIDRA
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
# Ghidra script for vm translator
#
# Usage:
#
# 1.Import this script.
#
# 2.Initial p-code Constructor
#
# @category VM

import ghidra
from array import *
from vm_utils import *
from vm_space import *
from ghidra.program.model.address import AddressSpace, GenericAddress
from ghidra.program.model.pcode import RawPcode, RawPcodeImpl, PcodeOp, Varnode

try:
    from ghidra.ghidra_builtins import *
except:
    pass

orig_hex = hex
def hex(x):
    if orig_hex(x)[-1] == 'L':
        return orig_hex(x)[:-1]
    else:
        return orig_hex(x)


class PcodeConstructor:

    def __init__(self, arch, address_fact):
        if arch == "x86-64":
            self.size = 8
        elif arch == "x86-32":
            self.size = 4
        elif arch == "x86-16":
            self.size = 2
        self.SPACE = {
            "unique": address_fact.uniqueSpace,
            "Register": address_fact.registerSpace,
            "RAM": address_fact.defaultAddressSpace,
            "const": address_fact.constantSpace,
        }

    def get_varnode(self, space, offset, size=None):
        if size is not None:
            return var_node(self.SPACE[space], offset, size)
        return var_node(self.SPACE[space], offset, self.size)

    def get_pcode(self, opcode, inputs, output=None):
        return RawPcodeImpl(opcode, inputs, output)

    def get_common_pcode(self, reg_offset):
        pcode_list = []
        # INT_SLESS
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x0)])
        output = self.get_varnode(REGISTER, 0x207, 1)
        int_sless = self.get_pcode(PcodeOp.INT_SLESS, inputs, output)
        pcode_list.append(int_sless)

        # INT_EQUAL
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x0)])
        output = self.get_varnode(REGISTER, 0x206, 1)
        int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
        pcode_list.append(int_equal)

        # INT_AND
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0xff)])
        output = self.get_varnode(UNIQUE, 0x12c00)
        int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
        pcode_list.append(int_and)

        # POPCOUNT
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c00)])
        output = self.get_varnode(UNIQUE, 0x12c80, 1)
        pop_count = self.get_pcode(PcodeOp.POPCOUNT, inputs, output)
        pcode_list.append(pop_count)

        # INT_AND
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c80, 1), self.get_varnode(CONSTANT, 0x1, 1)])
        output = self.get_varnode(UNIQUE, 0x12d00, 1)
        int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
        pcode_list.append(int_and)

        # INT_EQUAL
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12d00, 1), self.get_varnode(CONSTANT, 0x0, 1)])
        output = self.get_varnode(REGISTER, 0x202, 1)
        int_and = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
        pcode_list.append(int_and)
        return pcode_list

    def get_common_any_pcode(self, space, reg_offset):
        pcode_list = []
        # INT_SLESS
        inputs = array(Varnode, [self.get_varnode(space, reg_offset), self.get_varnode(CONSTANT, 0x0)])
        output = self.get_varnode(REGISTER, 0x207, 1)
        int_sless = self.get_pcode(PcodeOp.INT_SLESS, inputs, output)
        pcode_list.append(int_sless)

        # INT_EQUAL
        inputs = array(Varnode, [self.get_varnode(space, reg_offset), self.get_varnode(CONSTANT, 0x0)])
        output = self.get_varnode(REGISTER, 0x206, 1)
        int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
        pcode_list.append(int_equal)

        # INT_AND
        inputs = array(Varnode, [self.get_varnode(space, reg_offset), self.get_varnode(CONSTANT, 0xff)])
        output = self.get_varnode(UNIQUE, 0x12c00)
        int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
        pcode_list.append(int_and)

        # POPCOUNT
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c00)])
        output = self.get_varnode(UNIQUE, 0x12c80, 1)
        pop_count = self.get_pcode(PcodeOp.POPCOUNT, inputs, output)
        pcode_list.append(pop_count)

        # INT_AND
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c80, 1), self.get_varnode(CONSTANT, 0x1, 1)])
        output = self.get_varnode(UNIQUE, 0x12d00, 1)
        int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
        pcode_list.append(int_and)

        # INT_EQUAL
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12d00, 1), self.get_varnode(CONSTANT, 0x0, 1)])
        output = self.get_varnode(REGISTER, 0x202, 1)
        int_and = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
        pcode_list.append(int_and)
        return pcode_list

    def PUSH(self, reg):
        # COPY
        reg_offset = reg_offset_x86(reg)
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset)])
        output = self.get_varnode(UNIQUE, 0xe780)
        copy = self.get_pcode(PcodeOp.COPY, inputs, output)

        # INT_SUB
        sp = 0x20
        inputs = array(Varnode, [self.get_varnode(REGISTER, sp), self.get_varnode(CONSTANT, self.size)])
        output = self.get_varnode(REGISTER, sp)
        int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)

        # STORE
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1), self.get_varnode(REGISTER, sp),
                                 self.get_varnode(UNIQUE, 0xe780)])
        store = self.get_pcode(PcodeOp.STORE, inputs)

        return [copy, int_sub, store]

    def POP(self, reg):
        # LOAD
        reg_offset = reg_offset_x86(reg)
        sp = 0x20
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1), self.get_varnode(REGISTER, sp)])
        output = self.get_varnode(REGISTER, reg_offset)
        load = self.get_pcode(PcodeOp.LOAD, inputs, output)

        # INT_ADD
        inputs = array(Varnode, [self.get_varnode(REGISTER, sp), self.get_varnode(CONSTANT, self.size)])
        output = self.get_varnode(REGISTER, sp)
        int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)

        return [load, int_add]

    def MOV(self, reg, any_value):
        var_type = None
        # COPY
        reg_offset = reg_offset_x86(reg)
        if type(any_value) == str:
            var_type = REGISTER
            any_value = reg_offset_x86(any_value)
        elif type(any_value) == int:
            var_type = CONSTANT
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

        inputs = array(Varnode, [self.get_varnode(var_type, any_value)])
        output = self.get_varnode(REGISTER, reg_offset)
        copy = self.get_pcode(PcodeOp.COPY, inputs, output)

        return [copy]

    def MOV_FROM_PTR(self, reg, indirect):
        # TODO! add type check
        reg_name = indirect[0]
        reg0_offset = reg_offset_x86(reg_name)
        offset_0 = indirect[1]

        reg_offset = reg_offset_x86(reg)

        # INT_ADD
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg0_offset), self.get_varnode(CONSTANT, offset_0)])
        output = self.get_varnode(UNIQUE, 0x3200)
        int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)

        # LOAD
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1, 4), self.get_varnode(UNIQUE, 0x3200)])
        output = self.get_varnode(UNIQUE, 0xbd80)
        load = self.get_pcode(PcodeOp.LOAD, inputs, output)

        # COPY
        inputs = array(Varnode, [self.get_varnode(UNIQUE, 0xbd80)])
        output = self.get_varnode(REGISTER, reg_offset)
        copy = self.get_pcode(PcodeOp.COPY, inputs, output)

        return [int_add, load, copy]

    def MOV_TO_PTR(self, indirect, any_value):
        if type(any_value) == int:
            value_type = CONSTANT
        elif type(any_value) == str:
            value_type = REGISTER
            any_value = reg_offset_x86(any_value)
        # TODO! add type check
        reg_name = indirect[0]
        reg_offset = reg_offset_x86(reg_name)
        offset_0 = indirect[1]

        # INT_ADD
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, offset_0)])
        output = self.get_varnode(UNIQUE, 0x3100)
        int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)

        # COPY
        inputs = array(Varnode, [self.get_varnode(value_type, any_value)])
        output = self.get_varnode(UNIQUE, 0xbd80)
        copy = self.get_pcode(PcodeOp.COPY, inputs, output)

        # STORE
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1, 4), self.get_varnode(UNIQUE, 0x3100),
                                 self.get_varnode(UNIQUE, 0xbd80)])
        store = self.get_pcode(PcodeOp.STORE, inputs)

        return [int_add, copy, store]

    def JMP(self, any_value):

        if type(any_value) == str:
            # BRANCHIND
            reg_offset = reg_offset_x86(any_value)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset)])
            branch_ind = self.get_pcode(PcodeOp.BRANCHIND, inputs)

            return [branch_ind]
        elif type(any_value) == int or type(any_value) == long:
            # BRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, any_value)])
            branch = self.get_pcode(PcodeOp.BRANCH, inputs)

            return [branch]
        # TODO! add more type
        else:
            print("Unsupported JMP type!")
            return None

    def CALL(self, any_value, next_address=None):
        if type(any_value) == int:
            # INT_SUB
            sp = 0x20
            inputs = array(Varnode, [self.get_varnode(REGISTER, sp), self.get_varnode(CONSTANT, self.size)])
            output = self.get_varnode(REGISTER, sp)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)

            # STORE
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1), self.get_varnode(REGISTER, sp),
                                     self.get_varnode(CONSTANT, next_address)])
            store = self.get_pcode(PcodeOp.STORE, inputs)

            # CALL
            inputs = array(Varnode, [self.get_varnode(RAM, any_value)])
            call = self.get_pcode(PcodeOp.CALL, inputs)

            return [call]
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

    def LEA(self, reg, indirect):
        if type(indirect[0]) == int:
            # COPY
            offset = indirect[0]
            reg_offset = reg_offset_x86(reg)

            inputs = array(Varnode, [self.get_varnode(CONSTANT, offset)])
            output = self.get_varnode(REGISTER, reg_offset)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)
            return [copy]
        elif type(indirect[1]) == int:
            imm = indirect[1]
            reg_0 = indirect[0]
            reg_0_offset = reg_offset_x86(reg_0)
            reg_offset = reg_offset_x86(reg)

            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_0_offset), self.get_varnode(CONSTANT, imm)])
            output = self.get_varnode(UNIQUE, 0x3100)
            int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)

            # COPY
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x3100)])
            output = self.get_varnode(REGISTER, 0x0)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)

            return [int_add, copy]
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

    def JZ(self, any_value):
        if type(any_value) == int:
            # CBRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, any_value), self.get_varnode(REGISTER, 0x206, 1)])
            branch = self.get_pcode(PcodeOp.BRANCH, inputs)

            return [branch]
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

    def JNZ(self, any_value):
        if type(any_value) == int or type(any_value) == long:
            # BOOL_NEGATE
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x206, 1)])
            output = self.get_varnode(UNIQUE, 0xc680, 1)
            bool_negate = self.get_pcode(PcodeOp.BOOL_NEGATE, inputs, output)

            # CBRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, any_value), self.get_varnode(UNIQUE, 0xc680, 1)])
            branch = self.get_pcode(PcodeOp.BRANCH, inputs)

            return [bool_negate, branch]
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

    def CMP(self, reg, any_value):
        pcode_list = []
        if type(any_value) == str:
            # INT_LESS
            reg_offset = reg_offset_x86(reg)
            any_value = reg_offset_x86(any_value)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_LESS, inputs, output)
            pcode_list.append(int_less)

            # INT_SBORROW
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_SUB
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(UNIQUE, 0x28700)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
            pcode_list.append(int_sub)
        elif type(any_value) == int:
            # INT_LESS
            reg_offset = reg_offset_x86(reg)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_LESS, inputs, output)
            pcode_list.append(int_less)

            # INT_SBORROW
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_SUB
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(UNIQUE, 0x28700)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
            pcode_list.append(int_sub)
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

        common_pcode = self.get_common_any_pcode(UNIQUE, 0x28700)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list

    def CMP_TO_PTR(self, indirect, any_value):
        pcode_list = []
        if type(indirect[1]) == int:
            reg0_offset = reg_offset_x86(indirect[0])
            offset = indirect[1]
            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg0_offset), self.get_varnode(CONSTANT, offset)])
            output = self.get_varnode(UNIQUE, 0x3100)
            int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
            pcode_list.append(int_add)

            # LOAD
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1, 4), self.get_varnode(UNIQUE, 0x3100)])
            output = self.get_varnode(UNIQUE, 0xbd00, 4)
            load = self.get_pcode(PcodeOp.LOAD, inputs, output)
            pcode_list.append(load)

            # INT_LESS
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0xbd00, 4), self.get_varnode(CONSTANT, any_value, 4)])
            output = self.get_varnode(UNIQUE, 0x200, 1)
            load = self.get_pcode(PcodeOp.INT_LESS, inputs, output)
            pcode_list.append(load)

            # LOAD
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1, 4), self.get_varnode(UNIQUE, 0x3100)])
            output = self.get_varnode(UNIQUE, 0xbd00, 4)
            load = self.get_pcode(PcodeOp.LOAD, inputs, output)
            pcode_list.append(load)

            # INT_SBORROW
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0xbd00, 4), self.get_varnode(CONSTANT, any_value, 4)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
            pcode_list.append(int_sborrow)

            # LOAD
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x1b1, 4), self.get_varnode(UNIQUE, 0x3100)])
            output = self.get_varnode(UNIQUE, 0xbd00, 4)
            load = self.get_pcode(PcodeOp.LOAD, inputs, output)
            pcode_list.append(load)

            # INT_SUB
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0xbd00, 4), self.get_varnode(CONSTANT, any_value, 4)])
            output = self.get_varnode(UNIQUE, 0x28200, 4)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
            pcode_list.append(int_sub)

            # INT_SLESS
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x28200, 4), self.get_varnode(CONSTANT, 0x0, 4)])
            output = self.get_varnode(REGISTER, 0x207, 1)
            int_sless = self.get_pcode(PcodeOp.INT_SLESS, inputs, output)
            pcode_list.append(int_sless)

            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x28200, 4), self.get_varnode(CONSTANT, 0x0, 4)])
            output = self.get_varnode(REGISTER, 0x206, 1)
            int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_equal)

            # INT_AND
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x28200, 4), self.get_varnode(CONSTANT, 0xff, 4)])
            output = self.get_varnode(UNIQUE, 0x12c00, 4)
            int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
            pcode_list.append(int_and)

            # POPCOUNT
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c00, 4)])
            output = self.get_varnode(UNIQUE, 0x12c80, 1)
            int_and = self.get_pcode(PcodeOp.POPCOUNT, inputs, output)
            pcode_list.append(int_and)

            # INT_AND
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c80, 1), self.get_varnode(CONSTANT, 0x1, 1)])
            output = self.get_varnode(UNIQUE, 0x12d00, 1)
            int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
            pcode_list.append(int_and)

            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12d00, 1), self.get_varnode(CONSTANT, 0x0, 1)])
            output = self.get_varnode(REGISTER, 0x202, 1)
            int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_equal)

            return pcode_list
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

    def SUB(self, reg, any_value):
        pcode_list = []
        if type(any_value) == str:
            # INT_LESS
            reg_offset = reg_offset_x86(reg)
            any_value = reg_offset_x86(any_value)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_LESS, inputs, output)
            pcode_list.append(int_less)

            # INT_SBORROW
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_SUB
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
            pcode_list.append(int_sub)

        elif type(any_value) == int:
            # INT_LESS
            reg_offset = reg_offset_x86(reg)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_LESS, inputs, output)
            pcode_list.append(int_less)

            # INT_SBORROW
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_SUB
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
            pcode_list.append(int_sub)
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

        common_pcode = self.get_common_any_pcode(REGISTER, reg_offset)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list

    def INC(self, reg):
        pcode_list = []
        reg_offset = reg_offset_x86(reg)

        # INT_SCARRY
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x1)])
        output = self.get_varnode(REGISTER, 0x20b, 1)
        int_scarry = self.get_pcode(PcodeOp.INT_SCARRY, inputs, output)
        pcode_list.append(int_scarry)

        # INT_ADD
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x1)])
        output = self.get_varnode(REGISTER, reg_offset)
        int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
        pcode_list.append(int_add)

        common_pcode = self.get_common_any_pcode(REGISTER, reg_offset)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list

    def DEC(self, reg):
        pcode_list = []
        reg_offset = reg_offset_x86(reg)

        # INT_SBORROW
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x1)])
        output = self.get_varnode(REGISTER, 0x20b, 1)
        int_sborrow = self.get_pcode(PcodeOp.INT_SBORROW, inputs, output)
        pcode_list.append(int_sborrow)

        # INT_SUB
        inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, 0x1)])
        output = self.get_varnode(REGISTER, reg_offset)
        int_sub = self.get_pcode(PcodeOp.INT_SUB, inputs, output)
        pcode_list.append(int_sub)

        common_pcode = self.get_common_any_pcode(REGISTER, reg_offset)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list

    def ADD(self, reg, any_value):
        pcode_list = []
        if type(any_value) == str:
            # INT_CARRY
            reg_offset = reg_offset_x86(reg)
            any_value = reg_offset_x86(any_value)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_CARRY, inputs, output)
            pcode_list.append(int_less)

            # INT_SCARRY
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SCARRY, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_sub = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
            pcode_list.append(int_sub)

        elif type(any_value) == int:
            # INT_CARRY
            reg_offset = reg_offset_x86(reg)
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            int_less = self.get_pcode(PcodeOp.INT_CARRY, inputs, output)
            pcode_list.append(int_less)

            # INT_SCARRY
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, 0x20b, 1)
            int_sborrow = self.get_pcode(PcodeOp.INT_SCARRY, inputs, output)
            pcode_list.append(int_sborrow)

            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_sub = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
            pcode_list.append(int_sub)
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

        common_pcode = self.get_common_any_pcode(REGISTER, reg_offset)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list

    def JLE(self, address):
        pcode_list = []
        if type(address) == int or type(address) == long:
            # INT_NOTEQUAL
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x20b, 1), self.get_varnode(REGISTER, 0x207, 1)])
            output = self.get_varnode(UNIQUE, 0xcd80, 1)
            int_not_equal = self.get_pcode(PcodeOp.INT_NOTEQUAL, inputs, output)
            pcode_list.append(int_not_equal)

            # BOOL_OR
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x206, 1), self.get_varnode(UNIQUE, 0xcd80, 1)])
            output = self.get_varnode(UNIQUE, 0xce80, 1)
            bool_or = self.get_pcode(PcodeOp.BOOL_OR, inputs, output)
            pcode_list.append(bool_or)

            # CBRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, address), self.get_varnode(UNIQUE, 0xce80, 1)])
            c_branch = self.get_pcode(PcodeOp.CBRANCH, inputs)
            pcode_list.append(c_branch)

            return pcode_list

    def JGE(self, address):
        pcode_list = []
        if type(address) == int or type(address) == long:
            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x20b, 1), self.get_varnode(REGISTER, 0x207, 1)])
            output = self.get_varnode(UNIQUE, 0xcd00, 1)
            int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_equal)

            # CBRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, address), self.get_varnode(UNIQUE, 0xcd00, 1)])
            c_branch = self.get_pcode(PcodeOp.CBRANCH, inputs)
            pcode_list.append(c_branch)

            return pcode_list

    def JG(self, address):
        pcode_list = []
        if type(address) == int or type(address) == long:
            # BOOL_NEGATE
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x206, 1)])
            output = self.get_varnode(UNIQUE, 0xcf00, 1)
            bool_negate = self.get_pcode(PcodeOp.BOOL_NEGATE, inputs, output)
            pcode_list.append(bool_negate)

            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(REGISTER, 0x20b, 1), self.get_varnode(REGISTER, 0x207, 1)])
            output = self.get_varnode(UNIQUE, 0xcf80, 1)
            int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_equal)

            # BOOL_AND
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0xcf00, 1), self.get_varnode(UNIQUE, 0xcf80, 1)])
            output = self.get_varnode(UNIQUE, 0xd080, 1)
            bool_and = self.get_pcode(PcodeOp.BOOL_AND, inputs, output)
            pcode_list.append(bool_and)

            # CBRANCH
            inputs = array(Varnode, [self.get_varnode(RAM, address), self.get_varnode(UNIQUE, 0xd080, 1)])
            c_branch = self.get_pcode(PcodeOp.CBRANCH, inputs)
            pcode_list.append(c_branch)

            return pcode_list

    def TEST(self, reg, any_value):
        pcode_list = []

        # COPY
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x0, 1)])
        output = self.get_varnode(REGISTER, 0x200, 1)
        copy = self.get_pcode(PcodeOp.COPY, inputs, output)
        pcode_list.append(copy)

        # COPY
        inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x0, 1)])
        output = self.get_varnode(REGISTER, 0x20b, 1)
        copy = self.get_pcode(PcodeOp.INT_SCARRY, inputs, output)
        pcode_list.append(copy)

        reg_offset = reg_offset_x86(reg)

        if type(any_value) == str:
            any_value = reg_offset_x86(any_value)

            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(UNIQUE, 0x59300)
            int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
            pcode_list.append(int_add)

        elif type(any_value) == int:
            # INT_ADD
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(UNIQUE, 0x59300)
            int_add = self.get_pcode(PcodeOp.INT_ADD, inputs, output)
            pcode_list.append(int_add)
        # TODO! add more type
        else:
            print("Unsupported type!")
            return None

            # INT_SLESS
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x59300), self.get_varnode(CONSTANT, 0x0)])
            output = self.get_varnode(REGISTER, 0x207, 1)
            int_sless = self.get_pcode(PcodeOp.INT_SLESS, inputs, output)
            pcode_list.append(int_sless)

            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x59300), self.get_varnode(CONSTANT, 0x0)])
            output = self.get_varnode(REGISTER, 0x206, 1)
            int_equal = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_equal)

            # INT_AND
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x59300), self.get_varnode(CONSTANT, 0xff)])
            output = self.get_varnode(UNIQUE, 0x12c00)
            int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
            pcode_list.append(int_and)

            # POPCOUNT
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c00)])
            output = self.get_varnode(UNIQUE, 0x12c80, 1)
            pop_count = self.get_pcode(PcodeOp.POPCOUNT, inputs, output)
            pcode_list.append(pop_count)

            # INT_AND
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12c80, 1), self.get_varnode(CONSTANT, 0x1, 1)])
            output = self.get_varnode(UNIQUE, 0x12d00, 1)
            int_and = self.get_pcode(PcodeOp.INT_AND, inputs, output)
            pcode_list.append(int_and)

            # INT_EQUAL
            inputs = array(Varnode, [self.get_varnode(UNIQUE, 0x12d00, 1), self.get_varnode(CONSTANT, 0x0, 1)])
            output = self.get_varnode(REGISTER, 0x202, 1)
            int_and = self.get_pcode(PcodeOp.INT_EQUAL, inputs, output)
            pcode_list.append(int_and)

        return pcode_list

    def XOR(self, reg, any_value):
        pcode_list = []
        if type(any_value) == str:
            # COPY
            reg_offset = reg_offset_x86(reg)
            any_value = reg_offset_x86(any_value)
            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x0, 1)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)
            pcode_list.append(copy)

            # COPY
            output = self.get_varnode(REGISTER, 0x20b, 1)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)
            pcode_list.append(copy)

            # INT_XOR
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(REGISTER, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_xor = self.get_pcode(PcodeOp.INT_XOR, inputs, output)
            pcode_list.append(int_xor)

        elif type(any_value) == int:
            # COPY
            reg_offset = reg_offset_x86(reg)

            inputs = array(Varnode, [self.get_varnode(CONSTANT, 0x0, 1)])
            output = self.get_varnode(REGISTER, 0x200, 1)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)
            pcode_list.append(copy)

            # COPY
            output = self.get_varnode(REGISTER, 0x20b, 1)
            copy = self.get_pcode(PcodeOp.COPY, inputs, output)
            pcode_list.append(copy)

            # INT_XOR
            inputs = array(Varnode, [self.get_varnode(REGISTER, reg_offset), self.get_varnode(CONSTANT, any_value)])
            output = self.get_varnode(REGISTER, reg_offset)
            int_xor = self.get_pcode(PcodeOp.INT_XOR, inputs, output)
            pcode_list.append(int_xor)
            # TODO! add more type
        else:
            print("Unsupported type!")
            return None
        common_pcode = self.get_common_pcode(reg_offset)
        for pcode in common_pcode:
            pcode_list.append(pcode)
        return pcode_list
