#! /usr/bin/env python3
##
import binascii
import logging
import os
import sys
import time

import angr
import claripy
import r2pipe

# Prepare logging
logging.getLogger("angr.sim_manager").setLevel(logging.DEBUG)

# Config
binary = "./files/1a0ac4eb514b129844e15c2fad569f523c5701e146fffa3d51d6e5868b304da3"
if len(sys.argv) > 1:
    binary = sys.argv[1]


def get_state(p, stdin):
    # Prepare simulation manager
    st = p.factory.entry_state(
        stdin=stdin,
        add_options={
            *angr.options.unicorn,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    return st


def r2parse(binary):
    # Try three times cause r2pipe fucking sucks
    for _ in range(3):
        try:
            # Get addresses from offset via r2pipe
            r2 = r2pipe.open(binary)
            r2.cmd("aaa")

            # UNUSED: Better to calculate offset from main?
            # func_addr_str = r2.cmd("afl | tail -n 2 | head -n 1 | cut -d' ' -f1 | cut -d'x' -f 2")
            # func_addr = int(func_addr_str, 16)

            main_addr_str = r2.cmd("afl ~main | cut -d' ' -f1 | cut -d'x' -f 2")
            main_addr = int(main_addr_str, 16)

            find_addrs = [main_addr - 0x1A, main_addr - 0x2]
            avoid_addrs = [main_addr - 0x28]

            return (find_addrs, avoid_addrs)
        except Exception as e:
            print(f"ERROR WITH {binary}: {e}")
            time.sleep(1)
            continue


def main(binary):
    # Import project
    p = angr.Project(
        binary,
        auto_load_libs=False,
    )

    # Prepare stdin
    stdin_length = 32
    stdin_chars = [claripy.BVS("stdin_%d" % i, 8) for i in range(stdin_length)]
    stdin = claripy.Concat(*stdin_chars)

    # Prepare simulation manager
    st = get_state(p, stdin)

    # Constraint characters
    for k in stdin_chars:
        st.solver.add(k <= 0x7F)
        st.solver.add(k >= 0x20)

    # Get find_addrs and avoid_addrs
    find_addrs, avoid_addrs = r2parse(binary)
    print(f"{[hex(addr) for addr in find_addrs] = } {[hex(addr) for addr in avoid_addrs] = }")

    # Prepare simulation manager
    sm = p.factory.simulation_manager(st)

    # Explore!
    sm.explore(
        find=find_addrs,
        avoid=avoid_addrs,
        step_func=lambda s: print(hex(s.active[0].addr) if len(s.active) > 0 else "no"),
    )

    # Handle not found
    if len(sm.found) == 0:
        print("Found nothing!")
        with open("failed.txt", "a+") as file:
            file.write(binary + "\n")
    else:
        # Get found state
        print("Found states: ")
        for found in sm.found:
            password = found.solver.eval(stdin, cast_to=bytes).decode().strip()
            print(f"{password = }")
            print(f"{binascii.hexlify(password.encode()) = }")

            os.makedirs("./solutions", exist_ok=True)
            with open("./solutions/" + binary.split("/")[-1] + ".txt", "w") as file:
                file.write(password)


if __name__ == "__main__":
    # Check if solution already exists
    if os.path.exists("./solutions/" + binary.split("/")[-1] + ".txt"):
        print(f"{binary} already completed!")
        exit()

    # Run
    main(binary)
