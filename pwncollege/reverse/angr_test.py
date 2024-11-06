import angr
import claripy

# Ghidra loaded the binary to 0x00100000 (default Image Base)
base_addr = 0x00100000
 
proj = angr.Project('./babyrev_level19.0', main_opts={'base_addr': base_addr}, load_options={"auto_load_libs": False})

input_length = 15
 
# claripy.BVS('x', 8) => Create an eight-bit symbolic bitvector "x".
# Creating a symbolic bitvector for each character:
input_chars = [claripy.BVS("char_%d" % i, 8) for i in range(input_length)]
input = claripy.Concat(*input_chars)

entry_state = proj.factory.entry_state(args=["./babyrev_level19.0"], stdin=input)

for byte in input_chars:
    entry_state.solver.add(byte >= 0x20, byte <= 0x7e)

# Establish the simulation with the entry state
simulation = proj.factory.simulation_manager(entry_state)

success_addr = 0x00101489 # Address of "puts("Good Work!");"
failure_addr = 0x00101468 # Address of "puts("Try Harder");"
 
# Finding a state that reaches `success_addr`, while discarding all states that go through `failure_addr`
simulation.explore(find = success_addr, avoid = failure_addr)

# If at least one state was found
if len(simulation.found) > 0:
    # Take the first one and print what it evaluates to
    solution = simulation.found[0]
    print(solution.solver.eval(input, cast_to=bytes))
else:
    print("[-] no solution found :(")
