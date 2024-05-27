#!/usr/bin/python

import os
import subprocess
import sys
import time

# Backtraces tend to be pretty huge, this limits the output (we lose
# bottom frames, which are of no interest usually anyway). You can
# increase this limit if losing bottom frames is not an option for you.
BACKTRACE_LIMIT = 3007

EVENTS_DATA = "fdsnoop-events.data"
EVENTS_SCRIPT = "fdsnoop-events-script"

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

def del_probes(fatal):
    subprocess.run(["perf", "probe", "-q", "--del=open__return"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=dup__return"], check=fatal)
    subprocess.run(["perf", "probe", "-q", "--del=close"], check=fatal)

def record_events():
    # fast events
    print("Start recording events")

    subprocess.run(["perf", "record",
                    "-e", "probe_libc:open__return",
                    "-e", "probe_libc:close",
                    "-e", "probe_libc:dup__return",
                    "-a", "-p", str(pid),
                    "--call-graph", f"dwarf,{BACKTRACE_LIMIT}",
                    "-o", EVENTS_DATA,
                    "sleep", str(timeout)], check=True)

    print("All processes have finished")

# NOTE:
# If the registers change in the code we need to adjust probe-s accordingly
def probe_x86(pid, timeout):
    libc = libc_path()

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "open%return fd=$retval:s32"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "dup%return fd=$retval:s32"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "close fd=%di:s32"], check=True)

    print("Probes configured");
    record_events()

def probe_arm64(pid, timeout):
    libc = libc_path()

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "open%return ptr=$retval:s32"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "dup%return fd=$retval:s32"], check=True)

    subprocess.run(["perf", "probe", "-q", "-x", libc,
                    "close fd=%x0:s32"], check=True)

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

def usage():
    print("./fdsnoop.py process-name [timeout]")

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
