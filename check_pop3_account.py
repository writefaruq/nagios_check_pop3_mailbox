#!/usr/bin/env python
#
# ============================== SUMMARY =====================================
#
# Program : check_pop3_account.py
# Version : 1.0
# Date    : Aug 8 2014
# Author  : Faruque Sarker - writefaruq@gmail.com
# Credit  :Inspirted by the Nagios Plug-in check_pop3_account.pl by Jason Ellison - infotek@gmail.com
# Summary : This plugin logs into a POP3 or POP3 over SSL (POP3s) account and
#           reports the number of messages found.  It can optionally generate
#           alerts based on the number of messages found.  Performance data 
#           is available.
#
# License : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# ===================== INFORMATION ABOUT THIS PLUGIN =========================
#
# This program is written and maintained by: 
#   Faruque Sarker - writefaruq@gmail.com
#
# It is a full Python rewrite of a POP3 PERL plugin written by Jason Ellison.
#
# OVERVIEW
#
# This plugin logs into a POP3 or POP3 over SSL (POP3s) account and reports
# the number of messages found.  
# This plugin provides performance data in the form of the number of messages. 

# You may omit the warning and critical options if you are not concerned about
# the number of messages in the account. The protocol option may also be 
# ommited. If protocol is not defined it will default to POP3. 

# Usage: check_pop3_account.pl [-v] -H <host> -u <username> -p <password> \
#                              [-w <warning>] [-c <critical>] [-P <pop3|pop3s>]
# -h, --help
#        print this help message
# -v, --version :lllll
#        print version
# -V, --verbose
#        print extra debugging information
# -H, --host=HOST
#        hostname or IP address of host to check
# -u, --username=USERNAME
# -p, --password=PASSWORD
# -w, --warnng=INT
#        number of messages which if exceeded will cause a warning if ommited
#        just checks the account
# -c, --critical=INT
#        number of messages which if exceeded will cause a critical if ommited
#        just checks the account
# -P, --protocol=pop3|pop3s
#        protocol to use when checking messages (if omitted defaults to pop3)

# ============================= SETUP NOTES (Nagios integration not tested yet) ====================================
# 
# Copy this file to your Nagios installation folder in "libexec/". 
# Rename to "check_pop3_account.py"

# Manually test it with a command like the following:
# ./check_pop3_account.py -H pop.example.org -u username -p password

# NOTE: If you have special character in password/username remember to escape with a \ character

# NAGIOS SETUP : The following is UNTESTED. Use on your own risk.

# define command{
#   command_name check_pop3_account
#   command_line $USER1$/check_pop3_account.py -H $HOSTADDRESS$ -u $ARG1$ -p $ARG2$ -w $ARG3$  -c $ARG4$ -P $ARG5$
# }
#
# define service{
#   use generic-service
#   host_name MAILSERVER
#   service_description Check POP3 Account
#   check_command check_pop3_account!jellison!A$3cr3T!10!50!pop3
#   normal_check_interval 3
#   retry_check_interval 1
# }

import argparse
import poplib
import sys

PROTOCOL_POP3 = 'pop3'
PROTOCOL_POP3S = 'pop3s'
RET_CODES = {'OK': 0,
             'WARNING': 1,
             'CRITICAL': 2,
             'UNKNOWN': 3,
             'DEPENDENT': 4,
             }

def get_args():
    parser = argparse.ArgumentParser("Another Nagios plugin to check POP3 mailbox")
    parser.add_argument('-H', action='store', dest='host', required=True, help='hostname or IP address of Mail server host to check')
    parser.add_argument('-u', action='store', dest='user', required=True,  help='username')
    parser.add_argument('-p', action='store', dest='pswd', required=True, help='password')
    parser.add_argument('-w', action='store', dest='warning', help='number of messages which if exceeded will cause a warning', type=int, default=-1)
    parser.add_argument('-c', action='store', dest='critical', help='number of messages which if exceeded will cause a critical', type=int, default=-1)
    parser.add_argument('-P', action='store', dest='protocol', default='pop3', help='protocol to use when checking messages: pop3 | pop3s')
    return parser.parse_args()
    
def check_mailbox(host, user, pswd, protocol):
    """ Checks the mailbox and returns the count of messages"""
    mail_count = None
    try:
        if (protocol == PROTOCOL_POP3):
            mailbox = poplib.POP3(host)
        elif (protocol == PROTOCOL_POP3S):
            mailbox = poplib.POP3_SSL(host)
        else:
            raise Exception("Unknown protocol")
        if mailbox:
            mailbox.user(user)
            mailbox.pass_(pswd)
            mail_count = len(mailbox.list()[1])
    except Exception, e:
        print "Error occured: %s" %str(e)
        return
    return mail_count


if __name__ == '__main__':
    args = get_args()
    mail_count = check_mailbox(args.host, args.user, args.pswd, args.protocol)
    status_info = "%d emails for %s" %(mail_count, args.user)
    if mail_count is None:
        status_code = "CRITICAL"
        status_info = "Failed to login to server: %s with user: %s over: %s" %(args.host, args.user, args.protocol)
    elif ((args.critical > 0) and (mail_count >= args.critical)):
        status_code = "CRITICAL"
    elif ((args.warning > 0) and (mail_count >= args.warning)):
        status_code = "WARNING"
    else:
        status_code = "OK"

    print "POP3_ACCOUNT %s - %s |messages=%s;%s;%s" %(status_code, status_info, mail_count, args.warning, args.critical)
    sys.exit(RET_CODES[status_code])
