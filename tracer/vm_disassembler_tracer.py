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


# program stack used for the operations
stack = dict()
# global variables used during stack operations
# here will be stored the values extracted from
# the stack
g_vars = dict()
# number used as parameter for the function
fib_number = 1


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
    global stack
    global g_vars
    # fetch value of current virtual instruction pointer
    vip = sb.symbols[ExprId("RDX", 64)]
    vsp = sb.symbols[ExprId("RCX", 64)]
    var = sb.symbols[ExprId("RSI", 64)]
    r8 = sb.symbols[ExprId("R8",64)]

    # catch the individual handlers and print execution context
    if int(address) == 0x129e:
        first_val = stack[list(stack.keys())[-1]]
        second_val = stack[list(stack.keys())[-2]]
        
        print(f"{vip}: {second_val} <= {first_val} ", end="")
        
        # check ExprInt values and push if true or false
        if (int(second_val) <= int(first_val)):
            print("(true)")
            stack[list(stack.keys())[-1]] = ExprInt(1,32)
        else:
            print("(false)")
            stack[list(stack.keys())[-1]] = ExprInt(0,32)
        
        # clean one of the values from the stack
        stack.pop(list(stack.keys())[-2], None)

    elif int(address) == 0x1238:
        print(f"{vip}: [VM_STK] = *VAR")
        # retrieve from the top of the stack, the address
        top_stack = stack[list(stack.keys())[-1]]
        # insert the value pointed by a global var.
        stack[list(stack.keys())[-1]] = g_vars[top_stack]

    elif int(address) == 0x126d:
        
        # get the address pointed by vip
        address = expr_simp((vip + ExprInt(1,64)).signExtend(64))
        # get now the number in that address
        number = expr_simp(sb.symbols[ExprMem(address, 32)])

        print(f"{vip}: if [V_PC+1] == 0: push [r8] ({number} == 0)")

        # if the number is equals to zero,
        # push a value from r8 and create it
        # as variable.

        # R8 will hold a pointer to the parameter
        # of the fibonacci number
        if (number == ExprInt(0,32)):
            stack[vsp] = expr_simp(r8)
            g_vars[r8] = ExprInt(fib_number,32)


    elif int(address) == 0x11c4:

        # get the address pointed by vip
        address = expr_simp((vip + ExprInt(1,64)).signExtend(64))
        # get now the number in that address
        number = expr_simp(sb.symbols[ExprMem(address, 32)])
        # address of var
        local_var = expr_simp(var+number.zeroExtend(64))

        print(f"{vip}: PUSH ADDR [RSI+{number}] = {local_var}  (push address of local variable)")

        # push the address of local var on the stack
        stack[vsp] = local_var

    elif int(address) == 0x1262:
        # get the address where to jump and
        # calculate target
        address = expr_simp(vip + ExprInt(1,64))
        offset = expr_simp(sb.symbols[ExprMem(address, 32)]).zeroExtend(64)
        target = expr_simp(address + offset)
        print(f"{vip}: GOTO {target}")
    elif int(address) == 0x11a9:
        
        first_val = stack[list(stack.keys())[-1]]
        second_val = stack[list(stack.keys())[-2]]

        print(f"{vip}: [VM_STACK] = {first_val} + {second_val}")
        
        # remove the two values from the stack
        stack.pop(list(stack.keys())[-2], None)
        stack.pop(list(stack.keys())[-1], None)

        # push the result
        stack[vsp] = expr_simp(first_val + second_val)
        
    elif int(address) == 0x1245:
        print(f"{vip}: VM_RET")

        result = stack[list(stack.keys())[-1]]
        print("================================")
        print(f"| Result value: {result}            |")
        print("================================")

    elif int(address) == 0x11f1:
        # retrieve the values from the stack
        first_val = stack[list(stack.keys())[-1]]
        second_val = stack[list(stack.keys())[-2]]
        # clean the stack
        stack.pop(list(stack.keys())[-1], None)
        stack.pop(list(stack.keys())[-1], None)

        print(f"{vip}: {first_val} == {second_val} ", end="")
        
        # push the result as 1 for true, or 0 for false
        if (first_val == second_val):
            print("(true)")
            stack[vsp] = ExprInt(1,32)
        else:
            print("(false)")
            stack[vsp] = ExprInt(0,32)
        
    elif int(address) == 0x11e1:        
        # calculate address for bytecode
        address = expr_simp(vip + ExprInt(1, 64))
        # read from bytecode
        constant = expr_simp(sb.symbols[ExprMem(address, 32)])

        print(f"{vip}: PUSH {constant}")

        # write value on stack
        stack[vsp] = constant

    elif int(address) == 0x1281:

        address = expr_simp(vip + ExprInt(1,64))
        constant = expr_simp(sb.symbols[ExprMem(address, 32)])
        target = expr_simp(vip + constant.zeroExtend(64) + ExprInt(1, 64))
        print(f"{vip}: VM_COND_JUMP {target} ", end="")

        if stack[list(stack.keys())[-1]] == ExprInt(1,32):
            print("(taken)")
        else:
            print("(not taken)")

        # clean the stack from the boolean value
        stack.pop(list(stack.keys())[-1], None)

    elif int(address) == 0x1226:

        print(f"{vip}: POP VAR")
        top_stack = stack[list(stack.keys())[-1]]
        value = stack[list(stack.keys())[-2]]
        # remove stack
        stack.pop(list(stack.keys())[-1], None)
        stack.pop(list(stack.keys())[-1], None)
        # create global vars
        g_vars[top_stack] = value
    
    i = 0
    print("\t\t========STACK=========")
    for key, value in stack.items():
        if i == len(stack)-1:
            print(f"\t\tVM_SP => {key} ==> {value}")
        else:
            print(f"\t\t\t{key} ==> {value}")
        i += 1
    print("\t\t======================")


    print("\t\t========VARS=========")
    for key, value in g_vars.items():
        print(f"\t\t\t{key} ==> {value}")
    print("\t\t=====================")

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
sb.symbols[rdi] = ExprInt(fib_number, 64)

sb.symbols[ExprId("RCX", 64)] = ExprId("VM_STACK", 64)
sb.symbols[ExprId("RDX", 64)] = ExprId("VM_PC", 64)

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