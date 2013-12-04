#########################################################################################################################
# STIG lockdown script for Ubuntu OS
# 
# JAM
# LMN Solutions
# Version 0.1
# Dec 2013
#########################################################################################################################
# 
# This script is designed and tested for Ubuntu 12.03 and 12.04 LTS
# This script will only conduct system lockdowns on the unclassified
# DISA STIG documentation for the Ubuntu OS and application.
# This STIG is modified for Ubunto based on the RedHat and UNIX DISA STIGs
#
# This script assumes an "out of the box" Ubuntu install.  If there have been
# changes this script may or may not catch them, or may have false positive results.
# Also, this script only corrects findings that were not fixed by a manual review of
# the Ubuntu OS.  It does not check or fix any findings that were already compliant with
# the DISA STIG or were deemed site specific.
#

# Load the imports required by the script.
import os
import subprocess
import stat
import pexpect
import getpass

#########################################################################################################################
#
# CAT I Checks
#
#########################################################################################################################

#
# Rule-ID SV-28646r1 - OS must be a supported release
#
# Check if the OS is Ubuntu and is a supported ROGUE version
#
# Grab the OS version. Bend, fold, spindle, mutilate  - deteriorata - so that it can be verified
#
# First and foremost, using this script means you are using a supposted release for ROGUE
# Second, this scipt is intended for ROGUE use and if the OS changes, so will this script.

os_cmd_check = os.system('lsb_release -d')
os_text_string = os.popen('lsb_release -d').read().split()
os_text_version = os_text_string[2]
os_text_version = os_text_version.strip()

if os_cmd_check != 0:
    print 'Ubuntu version command failed. Not an Ubuntu OS or supported Ubuntu OS?\nExiting.'
    exit()

if (os_text_version != "12.03") and (os_text_version != "12.04"):
    print 'Unsupported version of Ubuntu detected.\nThis script supports Ubuntu 12.03 LTS and 12.04 LTS.\nExiting.\n'
    exit()

#
# Rule Id: SV-4268r5 - No special privlidge accounts
#
# If found, some of these accounts will be deleted.  Others will post a warning for additional verification.

SV_shutdown = os.system('grep "shutdown" /etc/passwd /etc/shadow')
SV_halt = os.system('grep "halt" /etc/passwd /etc/shadow')
SV_reboot = os.system('grep "reboot" /etc/passwd /etc/shadow')
SV_vagrant = os.system('grep "vagrant" /etc/passwd /etc/shadow')
SV_vboxadd = os.system('grep "vboxadd" /etc/passwd /etc/shadow')
SV_postgres = os.system('grep "postgres" /etc/passwd /etc/shadow')

#
# Specific STIG directed accounts
#

if SV_shutdown == 0:
    print 'Shutdown account found. Removing.\n'
    os.system('deluser shutdown')

if SV_halt == 0:
    print 'halt account found. Removing.\n'
    os.system('deluser halt')

if SV_reboot == 0:
    print 'reboot account found. Removing.\n'
    os.system('deluser reboot')

#
# Other application privileged users to verify.  Do not delete but note as a warning.
#
if SV_vagrant == 0:
    print 'Warning. Vagrant account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for future reference.\n'

if SV_vboxadd == 0:
    print 'Warning. Vboxadd account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for future reference.\n'

if SV_postgres == 0:
    print 'Warning. postgres account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for future reference.\n'

#
# Rule Id: SV-4339r5 - The Linux NFS Server must not have the insecure file locking option
#

nsfd_rule = os.system('pgrep -l nfsd')

if nsfd_rule == 0:
    print 'NFS Server process running. This is not inecessarily an issue unless the user has unrestricted privlidges.\n'

#
# Rule Id: SV-4342r5 - The x86 CTRL-ALT-Delete key sequence must be disabled.
#
# Read the /etc/init/control-alt-delete.conf file and comment out contents of file if not already done.
#

with open("/etc/init/control-alt-delete.conf", "r+") as data_file:
    lines = data_file.readlines()
    data_file.seek(0)
    data_file.truncate()
    for line in lines:
        if "start" in line:
            if "#" in line:
                data_file.write(line)
            else:   
                line = "# " + line
                data_file.write(line)
        elif "task" in line:
            if "#" in line:
                data_file.write(line)
            else:   
                line = "# " + line
                data_file.write(line)
        elif "exec" in line:
            if "#" in line:
                data_file.write(line)
            else:   
                line = "# " + line
                data_file.write(line)
        else:   
            data_file.write(line)
data_file.close()

#
# Rule Id: SV-28646r1 - Use approved DOD time clocks
# Replace Ubuntu default wit DOD approved
#
# Read text file with approved clocks and replace Ubuntu default in /etc/ntp.conf.
#

with open("/etc/ntp.conf", "r+") as ntp_conf_file:
    lines = ntp_conf_file.readlines()
    ntp_conf_file.seek(0)
    ntp_conf_file.truncate()
    count = 0
    for line in lines:
        if count == 0:
            if "Specify one or more NTP servers" in line:
                count = 1
                ntp_conf_file.write("\n")
                with open("./docs/ntp-servers.txt") as ntp_servers_file:
                    for ntp_line in ntp_servers_file:
                        ntp_conf_file.write(ntp_line)
            else:
                ntp_conf_file.write(line)
        elif count == 1:
            if "Access control configuration" in line:
                count = 2
                ntp_conf_file.write(line)
        elif count == 2:
                ntp_conf_file.write(line)
ntp_conf_file.close()

#
# Rule ID: SV-27109r1_rule - Remove nullok
#
# Remove nullok from /etc/pam.d scripts

nullok_check=os.system('sed -i s/nullok//g /etc/pam.d/*')
if nullok_check == 0:
    print 'Nullok removed from /etc/pam.d/*.\n'
else:
    print 'Nullok not found in /etc/pam.d. No files changed.\n'

#
# Rule Id: SV-4255r4 - The system boot loader must require authentication.
# Configure grub with root only authorization
#
# prompt for root boot loader password and configure grub config with new, secure, password.
#

# prompt for new boot loader password

#set password capture variables
pwd1=1
pwd2=2

while pwd1 != pwd2:
    pwd1 = getpass.getpass("Enter new Grub Loader Superuser Password:")
    pwd2 = getpass.getpass("Reenter new Grub Loader Superuser Password:")
    if pwd1 != pwd2:
        print "Passwords do not match."

# Feed password to the script
child = pexpect.spawn('grub-mkpasswd-pbkdf2')
child.expect ('Enter password:')
child.sendline (pwd1)
child.expect ('Reenter password:')
child.sendline (pwd1)
child.expect ('is ')
grub_pwd = child.readline()
grub_pwd = grub_pwd.strip()

# configure grub_40 file with new superuser access information
with open("/etc/grub.d/40_custom", "r+") as grub_40_file:
    lines = grub_40_file.readlines()
    grub_40_file.seek(0)
    grub_40_file.truncate()
    count = 0
    for line in lines:
        if " the \'exec tail\' line above" in line:
                grub_40_file.write(line)
                grub_40_file.write("\n")
                grub_40_file.write("set superusers=\"root\"\n")
                grub_40_file.write("\n")
                grub_40_file.write("password_pbkdf2 root %s" % grub_pwd)
                grub_40_file.write("\n")
                break
        else:
            grub_40_file.write(line)

# Update the grub.cfg file with the new superuser (root) access restriction

update_grub_check = os.system('update-grub')

if update_grub_check == 0:
    print 'Grub security updated.\n'
else:
    print 'Grub security update failed. Run manually after this script finishes.\n'

#########################################################################################################################
#
# End CAT I Checks
#
#########################################################################################################################
