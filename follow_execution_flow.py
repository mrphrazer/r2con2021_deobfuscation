#!/usr/bin/python3
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine


def constraint_memory(address, num_of_bytes):
    """
    Reads `num_of_bytes` from the binary at a given address
    and builds symbolic formulas to pre-configure the symbolic
    execution engine for concolinc execution.
    """
    global container
    # read bytes from binary
    byte_stream = container.bin_stream.getbytes(address, num_of_bytes)
    # build symbolic memory address
    sym_address = ExprMem(ExprInt(address, 64), num_of_bytes * 8)
    # build symbolic memory value
    sym_value = ExprInt(int.from_bytes(
        byte_stream, byteorder='little'), num_of_bytes * 8)

    return sym_address, sym_value


# check arguments
if len(sys.argv) != 2:
    print(f"[*] Syntax: {sys.argv[0]} <file>")
    exit()

# parse file path
file_path = sys.argv[1]

# address of vm entry
start_addr = 0x115a

# init symbol table
loc_db = LocationDB()
# read binary file
container = Container.from_stream(open(file_path, 'rb'), loc_db)
# get CPU abstraction
machine = Machine(container.arch)
# disassembly engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# initialize lifter to intermediate representation
lifter = machine.lifter_model_call(mdis.loc_db)

# disassemble the function at address
asm_cfg = mdis.dis_multiblock(start_addr)

# translate asm_cfg into ira_cfg
ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)

# init SE engine
sb = SymbolicExecutionEngine(lifter)

# constraint bytecode -- start address and size (highest address - lowest address)
# sym_address, sym_value = constraint_memory(0x4060, 0x4140 - 0x4060)
# sb.symbols[sym_address] = sym_value

# constraint VM input (rdi, first function argument). The value in `ExprInt` rerpesents the function's input value.
# rdi = ExprId("RDI", 64)
# sb.symbols[rdi] = ExprInt(0, 64)


# init worklist
basic_block_worklist = [ExprInt(start_addr, 64)]

# worklist algorithm
while basic_block_worklist:
    # get current block
    current_block = basic_block_worklist.pop()

    print(f"current block: {current_block}")

    # symbolical execute block -> next_block: symbolic value/address to execute
    next_block = sb.run_block_at(ira_cfg, current_block, step=False)

    print(f"next block: {next_block}")

    # is next block is integer or label, continue execution
    if next_block.is_int() or next_block.is_loc():
        basic_block_worklist.append(next_block)

# dump symbolic state
# sb.dump()

# dump VMs/functions' return value -- only works if SE runs until the end
# rax = ExprId("RAX", 64)
# value = sb.symbols[rax]
# print(f"VM return value: {value}")
