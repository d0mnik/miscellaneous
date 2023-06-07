import angr
import claripy

p = angr.Project('./appearance')
FUNC_START = 0x4011b4

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(40)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
state = p.factory.blank_state(addr=FUNC_START,stdin=flag)
for f in flag_chars:
    state.solver.add(f >= '\x20')
    state.solver.add(f <= '\x7e')
simulation = p.factory.simgr(state)

simulation.explore(find=0x401243, avoid=0x401260)

if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.solver.eval(flag,cast_to=bytes))
else:
    print('not found')
