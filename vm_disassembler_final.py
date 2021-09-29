#!/usr/bin/python3
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine


# hardcoded list of VM handlers taken from the binary
VM_HANDLERS = set([
    0x129e,
    0x1238,
    0x126d,
    0x11c4,
    0x1262,
    0x11a9,
    0x1245,
    0x11f1,
    0x11e1,
    0x1281,
    0x1226,
])


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

def disassemble(sb, address):
    """
    Callback to dump individual VM handler information,
    execution context etc.
    """
    # fetch concrete value of current virtual instruction pointer
    vip = sb.symbols[ExprId("RDX", 64)]

    # catch the individual handlers and print execution context
    if int(address) == 0x129e:
        print(f"{vip}: CMPBE")
    elif int(address) == 0x1238:
        print(f"{vip}: PUSHFROMVAR (load integer from local variable and push onto stack")
    elif int(address) == 0x126d:
        # calculate address for bytecode
        address = expr_simp((vip + ExprInt(1, 64)).signExtend(64))
        # read from bytecode
        constant = expr_simp(sb.symbols[ExprMem(address, 32)])
        print(f"{vip}: if {constant} == 0x0 then push var_c on top of stack")
    elif int(address) == 0x11c4:
        # calculate address for bytecode
        address = expr_simp((vip + ExprInt(1, 64)).signExtend(64))
        # read from bytecode
        constant = expr_simp(sb.symbols[ExprMem(address, 32)])
        print(f"{vip}: PUSHPTR var_{constant} (push pointer to local variable var_{constant})")
    elif int(address) == 0x1262:
        # calculate address for bytecode
        address = expr_simp((vip + ExprInt(1, 64)).signExtend(64))
        # read from bytecode
        constant = expr_simp(sb.symbols[ExprMem(address, 32)]).zeroExtend(64)
        # calculate address for vip
        goto_address = expr_simp(vip + constant + ExprInt(1, 64))
        print(f"{vip}: GOTO {goto_address}")
    elif int(address) == 0x11a9:
        print(f"{vip}: ADD")
    elif int(address) == 0x1245:
        print(f"{vip}: VMEXIT")
    elif int(address) == 0x11f1:
        print(f"{vip}: CMPE")
    elif int(address) == 0x11e1:
        # calculate address for bytecode
        address = expr_simp(vip + ExprInt(1, 64))
        # read from bytecode
        constant = expr_simp(sb.symbols[ExprMem(address, 32)])
        print(f"{vip}: PUSH {constant}")
    elif int(address) == 0x1281:
        print(f"{vip}: conditional jump")
    elif int(address) == 0x1226:
        print(f"{vip}: POPTOVAR (assign value to local variable)")


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
sym_address, sym_value = constraint_memory(0x4060, 0x4140 - 0x4060)
sb.symbols[sym_address] = sym_value

# constraint VM input (rdi, first function argument). The value in `ExprInt` rerpesents the function's input value.
rdi = ExprId("RDI", 64)
sb.symbols[rdi] = ExprInt(2, 64)


# init worklist
basic_block_worklist = [ExprInt(start_addr, 64)]

# worklist algorithm
while basic_block_worklist:
    # get current block
    current_block = basic_block_worklist.pop()

    # print(f"current block: {current_block}")

    # if current block is a VM handler, dump handler-specific knowledge
    if current_block.is_int() and int(current_block) in VM_HANDLERS:
        disassemble(sb, current_block)

    # symbolical execute block -> next_block: symbolic value/address to execute
    next_block = sb.run_block_at(ira_cfg, current_block, step=False)

    # print(f"next block: {next_block}")

    # is next block is integer or label, continue execution
    if next_block.is_int() or next_block.is_loc():
        basic_block_worklist.append(next_block)

# dump symbolic state
# sb.dump()

# dump VMs/functions' return value -- only works if SE runs until the end
# rax = ExprId("RAX", 64)
# value = sb.symbols[rax]
# print(f"VM return value: {value}")
