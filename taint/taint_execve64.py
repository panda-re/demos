#!/usr/bin/env python
'''
PANDA taint example, using the execve-test-overflow example 
from Chapter 11 of the Practical Binary Analysis book.

We mark all incoming network data as tainted, then check taint on execve.
We only look at the filename, not args for execve.

It should be noted that this differs from the Intel PIN example in the book
in that this is whole-sytem: we are looking at flow from any *recv* to *any* execve

Command to interact with VM directly if you want:
    $(python -m pandare.qcows x86_64)
or:
    panda-system-x86_64 /root/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2 -display none -m 1024 -loadvm root 
'''

from pandare import Panda
panda = Panda(generic='x86_64')

RECORDING_NAME = "overflow64"
taint_sources = {} # taint label -> details of where it came from (procname, data, insn_cnt)

if not panda.recording_exists(RECORDING_NAME):
    print(f"\n\nSTART: Create recording named {RECORDING_NAME}")
    connect_cmd ="echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/echo | nc -u 127.0.0.1 9999 -q 0 -w 0"

    @panda.queue_blocking
    def run_cmd():
        panda.revert_sync('root')

        # Copy the test program into the VM, compile it, and run it
        panda.copy_to_guest('testprog')
        print(panda.run_serial_cmd("gcc -o testprog/pwnme testprog/pwnme.c"))
        print(panda.run_serial_cmd("./testprog/pwnme & "))

        # While that's running in the background, record us connecting to it
        panda.record(RECORDING_NAME)
        print("\n\nIn-guest result:", panda.run_serial_cmd(connect_cmd))
        panda.end_record()
        panda.end_analysis()

    panda.run()
    print(f"DONE creating recording {RECORDING_NAME}")

if True: # Replay and show which processes ran. Then do it again and see that it's the same
    from pandare.extras import ProcGraph
    print("\n\nREPLAY ONE: Process graph")
    panda.pyplugins.load(ProcGraph, {'hide_ranges': True})
    panda.run_replay(RECORDING_NAME)

    print("\n\nREPLAY TWO: Process graph (again)")
    panda.pyplugins.load(ProcGraph, {'hide_ranges': True})
    panda.run_replay(RECORDING_NAME)

if True: # Syscall Trace
    print("\n\nREPLAY THREE: Syscall trace")
    panda.load_plugin("syscalls_logger", {'target': 'pwnme'})
    panda.run_replay(RECORDING_NAME)

if True: # Taint analysis
    @panda.ppp("syscalls2", "on_sys_recvfrom_enter")
    def pre_recvfrom(cpu, tb, fd, buf, size, flags, src, addrlen):
        # At the first recvfrom, turn on the taint system
        if not panda.taint_enabled():
            panda.taint_enable()

    @panda.ppp("syscalls2", "on_sys_recvfrom_return")
    def post_recvfrom(cpu, tb, fd, buf, size, flags, src, addrlen):
        # After a process has recv'd data, log it and mark it as tainted
        bytes_recvd = panda.arch.get_retval(cpu, convention='syscall')
        data = panda.virtual_memory_read(cpu, buf, bytes_recvd)
        print(f"Recvfrom read {bytes_recvd} bytes from fd {fd} into {buf:x} to get {data}")

        # Create a unique taint label for this data and store some info
        # associated with that label in taint_sources
        global taint_sources
        procname = panda.get_process_name(cpu) # Current process
        label = len(taint_sources)+1 # New, unique label
        insn_cnt = panda.rr_get_guest_instr_count() # How far into replay are we?
        taint_sources[label] = (procname, data, insn_cnt)

        # Label each byte in guest memory with this label
        phys_addr = panda.virt_to_phys(cpu, buf)
        for i in range(bytes_recvd):
            panda.taint_label_ram(phys_addr+i, label)

    @panda.ppp("syscalls2", "on_sys_execve_enter")
    def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
        if not panda.taint_enabled():
            return # Can't be relevant

        # If taint is enabled, this could have come from the network - check it
        phys_addr = panda.virt_to_phys(cpu, fname_ptr)
        tainted = panda.taint_check_ram(phys_addr)

        fname = panda.read_str(cpu, fname_ptr)
        print(f"Execve of {fname}")
        if tainted:
            global taint_sources
            print("\tTAINTED DATA!")
            for label in panda.taint_get_ram(phys_addr):
                procname, data, insn_cnt = taint_sources[label]
                print(f"\tData from {procname}'s recv at insn #{insn_cnt}: {repr(data)}")

    panda.run_replay(RECORDING_NAME)