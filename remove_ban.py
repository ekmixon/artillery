#!/usr/bin/python
#
# simple remove banned ip
#
#
import sys
from src.core import *

try:
    ipaddress = sys.argv[1]
    if is_valid_ipv4(ipaddress):
        path = check_banlist_path()
        fileopen = file(path, "r")
        data = fileopen.read()
        data = data.replace(ipaddress + "\n", "")
        filewrite = file(path, "w")
        filewrite.write(data)
        filewrite.close()

        print("Listing all iptables looking for a match... if there is a massive amount of blocked IP's this could take a few minutes..")
        proc = subprocess.Popen(
            f"iptables -L ARTILLERY -n -v --line-numbers | grep {ipaddress}",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )


        for line in proc.stdout.readlines():
            line = str(line)
            if match := re.search(ipaddress, line):
                # this is the rule number
                line = line.split(" ")
                line = line[0]
                print(line)
                # delete it
                subprocess.Popen(
                    f"iptables -D ARTILLERY {line}",
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    shell=True,
                )


    else:
        print("[!] Not a valid IP Address. Exiting.")
        sys.exit()

except IndexError:
    print("Description: Simple removal of IP address from banned sites.")
    print("[!] Usage: remove_ban.py <ip_address_to_ban>")
