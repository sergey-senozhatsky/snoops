# SPDX-License-Identifier: GPL
#!/usr/bin/python

import os
import subprocess
import sys
import time

# Backtraces tend to be pretty huge, this limits the output (we lose
# bottom frames, which are of no interest usually anyway). You can
# increase this limit if losing bottom frames is not an option for you.
BACKTRACE_LIMIT = 3007

EVENTS_DATA = "memsnoop-events.data"
AUX_EVENTS_DATA = "memsnoop-origins.data"
EVENTS_SCRIPT = "memsnoop-events-script"
AUX_EVENTS_SCRIPT = "memsnoop-origins-script"

def libc_path():
    if os.path.isfile("/lib64/libc.so.6"):
        return "/lib64/libc.so.6"

    print("Error: libc not found")
    sys.exit(1)

def get_pid(process_name):
    try:
        pid = int(subprocess.check_output(["pidof", process_name]))
        return pid
    except subprocess.CalledProcessError:
        return None

# probes are common for arm64 and x86
def del_probes(fatal):
    subprocess.run(["perf", "probe", "-q",
                    "--del=malloc__return"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=malloc"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=free"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=mmap__return"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=mmap"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=munmap"], check=fatal)
    subprocess.run(["perf", "probe", "-q",
                    "--del=handle_mm_fault"], check=fatal)

def record_events():
    # pause process before we spawn recorders
    subprocess.run(["kill", "-SIGSTOP", str(pid)], check=True)

    # fast events
    print("Start recording events")
    command = ["perf", "record",
               "-e", "probe_libc:malloc__return",
               "-e", "probe_libc:free",
               "-e", "probe:handle_mm_fault",
               "-e", "probe_libc:mmap__return",
               "-e", "probe_libc:munmap",
               "-a", "-p", str(pid),
               "-o", EVENTS_DATA,
               "sleep", str(timeout)]

    events = subprocess.Popen(command,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL,
                              close_fds=True)
    # backtrace enriched events
    print("Start recording aux events")
    command = ["perf", "record",
               "-e", "probe_libc:malloc",
               "-e", "probe_libc:mmap",
               "-a", "-p", str(pid),
               "--call-graph", f"dwarf,{BACKTRACE_LIMIT}",
               "-o", AUX_EVENTS_DATA,
               "sleep", str(timeout)]

    aux_events = subprocess.Popen(command,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  stdin=subprocess.DEVNULL,
                                  close_fds=True)

    # carry on
    subprocess.run(["kill", "-SIGCONT", str(pid)], check=True)

    events.wait()
    aux_events.wait()
    print("All processes have finished")

# NOTE:
# If the registers change in the code we need to adjust probe-s accordingly
#
# NOTE:
# it seems to be impossible to capture $retval and %x0/%di in one probe event
# (the register gets corrupted). Hence we split malloc events in order to
# properly capture arguments and return values.
def probe_x86(pid, timeout):
    libc = libc_path()

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "malloc%return ptr=$retval"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "malloc sz=%di:u64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "mmap%return ptr=$retval"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "mmap sz=%si:u64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "munmap ptr=%di:x64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "free ptr=%di:x64"], check=True)

    # this needs KPROBES
    subprocess.run(["perf", "probe", "-q", "handle_mm_fault ptr=%si:x64"],
                   check=True)

    print("Probes configured");
    record_events()

def probe_arm64(pid, timeout):
    libc = libc_path()

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "malloc%return ptr=$retval"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "malloc sz=%x0:u64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "free ptr=%x0:x64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "mmap%return ptr=$retval"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "mmap sz=%x1:u64"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "munmap ptr=%x0:x64"], check=True)

    # this needs KPROBES
    subprocess.run(["perf", "probe", "-q", "handle_mm_fault ptr=%x1:x64"],
                   check=True)

    print("Probes configured")
    record_events()

def probe(pid, timeout):
    arch = os.uname().machine

    del_probes(False)
    if arch == "aarch64":
        probe_arm64(pid, timeout)
    else:
        probe_x86(pid, timeout)
    del_probes(True)

    with open(EVENTS_SCRIPT, "w") as output_file:
        proc = subprocess.Popen(["perf", "script", "-i", EVENTS_DATA],
                                stdout=output_file)
        proc.wait()
        output_file.close()
        print(f"*** {EVENTS_SCRIPT} is ready")
        os.remove(EVENTS_DATA)

    with open(AUX_EVENTS_SCRIPT, "w") as output_file:
        proc = subprocess.Popen(["perf", "script", "-i", AUX_EVENTS_DATA],
                                stdout=output_file)
        proc.wait()
        output_file.close()
        print(f"*** {AUX_EVENTS_SCRIPT} is ready")
        os.remove(AUX_EVENTS_DATA)

def usage():
    print("./memsnoop.py process-name [timeout]")

if __name__ == "__main__":
    timeout = 10

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    process_name = sys.argv[1]
    if (len(sys.argv) == 3):
        timeout = int(sys.argv[2])
    pid = get_pid(process_name)

    if pid is None:
        print(f"Error: unable to pidof {process_name}")
        sys.exit(1)

    print(f"snooping {process_name}/{pid} for {timeout} seconds")
    probe(pid, timeout)
