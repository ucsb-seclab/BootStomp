"""
IDAPython script to find all occurrences of a particular opcode
and all those distinct functions where that opcode is used, once or more.
Instructions which do not lie in any method recognized by IDA, the script treats
each of those to be self-contained, short and distinct methods on it own
"""

import idc
from idaapi import *


instr_addresses = []    # Addresses of instructions containing the opcode
instr_func_addresses = set()    # Names of distinct methods where those instructions occur in


def find_instr(instr, seg_start = get_segm_start(ea), seg_end = get_segm_end(ea)):
    """
    Finds machines instructions using the particular opcode
    Input: instr => Opcode to be searched for
           seg_start => The address for the search to begin from (optional), default is the starting address of the segment
           seg_end => The address for the search to end at (optional), default is the ending address of the segment
    Output: instr_addresses => Addresses of instructions containing the particular opcode
            instr_func_addresses => Names of distinct methods where those instructions occur in
    """
    addr = seg_start

    # Iterate over the address space ocupied by the image
    while addr <= seg_end:
        instr_address = FindText(addr, SEARCH_DOWN, 0, 0, instr)
        instr_addresses.append(instr_address)
        instr_belogs_to_func = get_func(instr_address)

        # Check if the instruction lies in a function recognized by IDA
        if instr_belogs_to_func is not None:
            instr_func_addresses.add(get_func_name(instr_belogs_to_func.start_ea))   # Get the mnemonic function named by IDA
        else:
            instr_func_addresses.add("instr_" + str(instr_address))     # Name the function in the form of "instr_<address>""

        # On ARM, instructions are fixed sized (4 bytes)
        addr = instr_address + 4


instr = "BLR"   # Search for BLR, the absolute jump
find_instr(instr)
print("{} occurrences: ".format(instr), len(instr_addresses))
print("Distinct functions: ", len(instr_func_addresses))
