#!/usr/bin/python3
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine

# check arguments
if len(sys.argv) != 3:
    print(f"[*] Syntax: {sys.argv[0]} <file> <address>")
    exit()

# parse arguments
file_path = sys.argv[1]
start_addr = int(sys.argv[2], 16)

# symbol table
loc_db = LocationDB()

# open the binary for analysis
container = Container.from_stream(open(file_path, 'rb'), loc_db)

# cpu abstraction
machine = Machine(container.arch)

# init disassemble engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# initialize lifter to intermediate representation
lifter = machine.lifter_model_call(mdis.loc_db)

# disassemble the function at address
asm_cfg = mdis.dis_multiblock(start_addr)

# translate asm_cfg into ira_cfg
ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)

# init SE engine
sb = SymbolicExecutionEngine(lifter)

# symbolically execute basic block
next_block = sb.run_block_at(ira_cfg, start_addr)

# dump symbolic state
sb.dump()