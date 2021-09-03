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
# Ghidra script for vm utils
#
# Usage:
#
# 1.Import this script.
#
# @category VM

import ghidra
from array import *

from ghidra.program.model.pcode import RawPcode, RawPcodeImpl, Varnode

try:
    from ghidra.ghidra_builtins import *
except:
    pass

X86_REGS = {
    "ax": 0x0,
    "bx": 0x18,
    "cx": 0x8,
    "dx": 0x10,
    "si": 0x30,
    "di": 0x38,
    "sp": 0x20,
    "bp": 0x28,
    "r8": 0x80,
    "r9": 0x88,
    "r10": 0x90,
    "r11": 0x98,
    "r12": 0xa0,
    "r13": 0xa8,
    "r14": 0xb0,
    "r15": 0xb8,
}


def reg_offset_x86(reg):
    reg_name = reg.lower()
    if reg_name[-1:].isalpha():
        reg_name = reg_name[-2:]

    return X86_REGS[reg_name]


def var_node(space, offset, size):
    address = space.getAddress(offset)

    return Varnode(address, size)
