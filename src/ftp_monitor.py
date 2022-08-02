#!/usr/bin/python

#############################
#
# monitor ftp and ban
# added by e @ Nov 5th
#############################

import time
import re
try: import thread
except ImportError: import _thread as thread
from src.core import *

send_email = read_config("ALERT_USER_EMAIL")

# how frequently we need to monitor
monitor_time = read_config("MONITOR_FREQUENCY")
monitor_time = int(monitor_time)
ftp_attempts = read_config("FTP_BRUTE_ATTEMPTS")
# check for whitelist

from . import globals

def ftp_monitor(monitor_time):
    while 1:
        # for debian base
        if os.path.isfile("/var/log/vsftpd.log"):
            fileopen1 = file("/var/log/auth.log", "r")
        else:
            print("Has not found configuration file for ftp. Ftp monitor now stops.")
            break

        if not os.path.isfile(globals.g_banlist):
            # create a blank file
            filewrite = file(globals.g_banlist, "w")
            filewrite.write("")
            filewrite.close()

        try:
            # base ftp counter to see how many attempts we've had
            ftp_counter = 0
            counter = 0
            for line in fileopen1:
                counter = 0
                fileopen2 = file(globals.g_banlist, "r")
                line = line.rstrip()
                if match := re.search("CONNECT: Client", line):
                    ftp_counter = ftp_counter + 1
                    # split based on spaces
                    line = line.split('"')
                    # pull ipaddress
                    ipaddress = line[-2]
                    ip_check = is_valid_ipv4(ipaddress)
                    if ip_check != False and ftp_counter >= int(ftp_attempts):
                        banlist = fileopen2.read()
                        match = re.search(ipaddress, banlist)
                        if match:
                            counter = 1
                            # reset FTP counter
                            ftp_counter = 0

                            # if counter is equal to 0 then we know that we
                            # need to ban
                        if counter == 0:
                            whitelist_match = whitelist(ipaddress)
                            if whitelist_match == 0:

                                # if we have email alerting on we can send
                                # email messages
                                email_alerts = read_config(
                                    "EMAIL_ALERTS").lower()
                                # check email frequency
                                email_frequency = read_config(
                                    "EMAIL_FREQUENCY").lower()

                                if email_alerts == "on" and email_frequency == "off":
                                    mail(
                                        send_email,
                                        "[!] Artillery has banned an FTP brute force. [!]",
                                        f"The following IP has been blocked: {ipaddress}",
                                    )


                                    # check frequency is allowed
                                if email_alerts == "on" and email_frequency == "on":
                                    prep_email(
                                        f"Artillery has blocked (blacklisted) the following IP for FTP brute forcing violations: {ipaddress}"
                                        + "\n"
                                    )


                                    # write out to log
                                write_log(
                                    f"Artillery has blocked (blacklisted) the following IP for FTP brute forcing violations: {ipaddress}"
                                )


                                # do the actual ban, this is pulled from
                                # src.core
                                ban(ipaddress)
                                ftp_counter = 0

                                # wait one to make sure everything is
                                # caught up
                                time.sleep(1)
            # sleep for defined time
            time.sleep(monitor_time)

        except Exception as e:
            print(f"[*] An error in ftp monitor occured. Printing it out here: {str(e)}")

if is_posix():
    # start thread
    thread.start_new_thread(ftp_monitor, (monitor_time,))
