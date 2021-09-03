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
# Ghidra script for brainfuvk decompile
# This script can decompile bf code to pseudo-code.
#
# Currently only supports setting the bf code in the script.
#
# Usage:
#
# 1.Choose a program for patch p-code.
#
# 2.Set function address in this script.
#
# 3.Set the bf code in this script.
#
# 3.Run script.
# @category VM

from vm_decompile_x86_pcode import PcodeConstructor

# defined function address
func_write = 0x0302010
func_read = 0x0302028


class BrainFuck:
    def __init__(self, construct, inst, stack_var):
        self.c = construct
        self.inst_next = inst
        self.stack_var = stack_var

    def right(self):
        self.stack_var = [self.stack_var[0], self.stack_var[1] + 0x8]

    def left(self):
        self.stack_var = [self.stack_var[0], self.stack_var[1] - 0x8]

    def increase(self):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV_FROM_PTR("RAX", self.stack_var))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.INC("RAX"))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV_TO_PTR(self.stack_var, "RAX"))

    def decrease(self):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV_FROM_PTR("RAX", self.stack_var))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.DEC("RAX"))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV_TO_PTR(self.stack_var, "RAX"))

    def write(self):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RDI", 0x1))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.LEA("RAX", self.stack_var))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RSI", "RAX"))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RDX", 0x8))

        self.inst_next = getInstructionAfter(self.inst_next)
        inst_next_address = getInstructionAfter(self.inst_next).getAddress().offset
        self.inst_next.patchPcode(self.c.CALL(func_write, inst_next_address))

    def read(self):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RDI", 0x0))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.LEA("RAX", self.stack_var))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RSI", "RAX"))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV("RDX", 0x1))

        self.inst_next = getInstructionAfter(self.inst_next)
        inst_next_address = getInstructionAfter(self.inst_next).getAddress().offset
        self.inst_next.patchPcode(self.c.CALL(func_read, inst_next_address))

    def LOOP_START(self, end_addr):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.MOV_FROM_PTR("R8", self.stack_var))

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.JMP(end_addr))

    def LOOP_END(self, star_addr):
        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.CMP_TO_PTR(self.stack_var, 0x0))
        end_address = self.inst_next.getAddress().offset

        self.inst_next = getInstructionAfter(self.inst_next)
        self.inst_next.patchPcode(self.c.JG(star_addr))
        return end_address


if __name__ == '__main__':
    code = "++++++++++[" \
           ">+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>."

    # init pcode constructor
    arch = "x86-64"
    address_fact = currentProgram.getAddressFactory()
    constructor = PcodeConstructor(arch, address_fact)

    # patch start address
    current_addr = address_fact.getAddress(hex(0x0100724))

    # If you need bigger stack space, modify the size.

    # init stack[size]
    stack_var = ["RBP", -0x100]
    inst = getInstructionAt(current_addr)
    sub = constructor.ADD("RSP", stack_var[1])
    inst.patchPcode(sub)
    inst_next = getInstructionAfter(inst)
    bf = BrainFuck(constructor, inst_next, stack_var)
    xor = constructor.XOR("RDX", "RDX")
    inst_next.patchPcode(xor)

    # bf interpreter
    loop_stack = []
    for c in code:
        if c == '+':
            bf.increase()
        elif c == '-':
            bf.decrease()
        elif c == '<':
            bf.left()
        elif c == '>':
            bf.right()
        elif c == ',':
            bf.read()
        elif c == '.':
            bf.write()
        elif c == '[':
            start_inst = bf.inst_next
            start_stack = bf.stack_var
            loop_stack.append((start_inst, start_stack))

            bf.LOOP_START(start_inst.getAddress().offset)
        elif c == ']':
            start_inst, start_stack = loop_stack.pop()
            ins = start_inst
            for i in range(3):
                ins = getInstructionAfter(ins)
            start_address = ins.getAddress().offset
            end_address = bf.LOOP_END(start_address)

            current_inst = bf.inst_next
            current_stack = bf.stack_var

            bf.inst_next = start_inst
            bf.stack_var = start_stack

            bf.LOOP_START(end_address)

            bf.inst_next = current_inst
            bf.stack_var = current_stack
    print("Complete!")
