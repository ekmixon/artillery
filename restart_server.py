#!/usr/bin/python
#
# restart artillery
#
#
import subprocess
import os
import signal
from src.core import *

init_globals()

proc = subprocess.Popen(
    "ps -A x | grep artiller[y].py", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
# kill running instance of artillery
kill_artillery()

print(f"[*] {grab_time()}: Restarting Artillery Server...")
if os.path.isfile("/var/artillery/artillery.py"):
    write_log("Restarting the Artillery Server process...",1)
    subprocess.Popen("python /var/artillery/artillery.py &",
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
