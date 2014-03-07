#########################################################################################################################
# STIG lockdown script for Ubuntu OS
# 
# JAM
# LMN Solutions
# Version 0.9
# March 2014
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
import os.path
import subprocess
import stat
import getpass

# Install python-pexpect since it is required by the script.

# check if installed. If not, install it.
#

pexpect_check=os.system('dpkg --get-selections | grep pexpect')

if pexpect_check != 0:
    os.system('apt-get install python-pexpect')
    import pexpect
else:
    import pexpect

# Declare variables
date_time_now=os.popen('date').read()

#########################################################################################################################
#
# Get the system administrator user naem for use in some of the scripts
#
#########################################################################################################################

print 'Get system administrator account name to configure administrator funstions identified by the STIG.\n'

admin1=1
admin2=2

while admin1 != admin2:
    admin1 = raw_input("Enter system administrator account name:")
    admin2 = raw_input("Reenter system administrator account name:")
    if admin1 != admin2:
        print "Entered system administrator account name does not match."


#########################################################################################################################
#
# Install any of the necessary packages for the system lockdown.  Install upfront since CAT changes are not always in
# order. Any STIG required configuration will also be done as part of the ins
#
#########################################################################################################################

print 'Installing STIG required packages.\n'

#
# SV-27270r1_rule. Auditing must be implemented.
#
# This script is upfront to allow for changes to the /etc/pam.d/common-auth changes that will be implemented for STIGs
# later in the script.
#

# install auditd

os.system('apt-get install auditd')

# rotate the logs daily

os.system('cp ./doc/auditd /etc/cron.daily;chmod 700 /etc/cron.daily/auditd;chown root:root /etc/cron.daily/auditd')

#
# Rule Id: SV-12442-1r6
# Rule Title: A file integrity baseline must be created.
#
# The following installs tripwire and initiates the baseline if tripwire install not found

trip_check=os.system('which tripwire')
if trip_check != 0:
    os.system('apt-get install tripwire && tripwire --init')

#
# Sendmail  and postfix - not spelled out in the STIGs per say but is necessary to send administrator email in a number of 
# the STIG changes.
#

os.system('apt-get install sendmail')
os.system('apt-get install postfix')

#########################################################################################################################
#
# Purge STIG identified packages.  Purge up front so that not being done off and on during the installation.
#
#########################################################################################################################

print 'Purging STIG required packages.\n'

#
# SV-26666r1_rule - The portmap or rpcbind service must not be installed unless needed.
#
# Removes rpcbind and portmap
#

os.system('apt-get purge rpcbind')

#
# SV-12550r5_rule - Network analysis tools must not be installed
#
# Removes tcpdump and mitigates nc.openbsd
#

os.system('apt-get purge tcpdump')
os.system('chmod 0000 /bin/nc.openbsd')

#########################################################################################################################
#
# Start CAT I Checks
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
    print 'Warning. Vagrant account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for follow-on analysis.\n'

if SV_vboxadd == 0:
    print 'Warning. Vboxadd account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for follow-on analysis.\n'

if SV_postgres == 0:
    print 'Warning. postgres account found. This is not inecessarily an issue unless the user has unrestricted privlidges. Noted for follow-on analysis.\n'

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
                with open("./doc/ntp-servers.txt") as ntp_servers_file:
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
grub_40_file.close()

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

#########################################################################################################################
#
# Start CAT II Checks
#
#########################################################################################################################

#
# Rule Id: SV-29956r1 - The /etc/gshadow file must be group-owned by root
# Change /etc/gshadow to root if not root.  OOB is shadow.
#
if os.path.exists("/etc/gshadow"):
    gsown = os.system('stat -c %G /etc/gshadow')
    if gsown != "root":
        print '/etc/gshadow file group changed to root.\n'
        os.system('chgrp root /etc/gshadow')
    else:
        print '/etc/gshadow file group is already owned by root.\n'
else:
    print '/etc/gshadow does not exist.\n'

# Add the STIG audit rules
# SV-27291r1_rule, SV-27295r1_rule, SV-27302r1_rule
# Plus change the buffers for the busy system

with open("/etc/audit/audit.rules", "r+") as audit_rules_file:
    lines = audit_rules_file.readlines()
    audit_rules_file.seek(0)
    for line in lines:
        if '-b 320' in line:
            audit_rules_file.write("# Increased for database and or Geoserver \n")
            audit_rules_file.write("-b 750\n")
            audit_rules_file.write("\n")
            audit_rules_file.write("# STIG Based Audits\n")
        elif '# Feel free to add below this line' in line:
            audit_rules_file.write(line)
            audit_rules_file.write("\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S open -F success=0\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S unlink -S rmdir\n")
            audit_rules_file.write("-w /etc/audit/auditd.conf\n")
            audit_rules_file.write("-w /etc/audit/audit.rules\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S adjtimex -S settimeofday -k time-change\n")
            audit_rules_file.write("-a always,exit -F arch=b32 -S stime -k time-change\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S sethostname -S setdomainname -k system-locale\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S clock_settime -k time-change\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S sched_setparam -S sched_setscheduler\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S chmod -S fchmod -S fchmodat -S chown -S fchown -k perm_mod\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S fchownat -S lchown -S setxattr -S lsetxattr -S fsetxattr -k perm_mod\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S removexattr -S lremovexattr -S fremovexattr -k perm_mod\n")
            audit_rules_file.write("-a always,exit -F arch=b32 -S chown32 -S fchown32 -S lchown32 -k perm_mod\n")
            audit_rules_file.write("-a always,exit -F arch=x86_64 -S init_module -S delete_module -k modules\n")
            audit_rules_file.write("-w /sbin/insmod -p x -k modules\n")
            audit_rules_file.write("-w /sbin/modprobe -p x -k modules\n")
            audit_rules_file.write("-w /sbin/rmmod -p x -k modules\n")
        else:
            audit_rules_file.write(line)
audit_rules_file.close()

#
# SV-26518r1_rule. The audit system must alert the SA when the audit storage volume approaches its capacity.
#
# This changes the /etc/audit/audit.conf to email the administrator when the storage volume is reached.
# It uses the admin account name set above.  
#

with open("/etc/audit/auditd.conf", "r+") as audit_conf_file:
    lines = audit_conf_file.readlines()
    audit_conf_file.seek(0)
    for line in lines:
        if 'space_left_action' in line:
            audit_conf_file.write("space_left_action = email\n")
        elif 'action_mail_acct' in line:
            audit_conf_file.write("action_mail_acct = %s\n" %str(admin1))
audit_conf_file.close()

#
# Rule Id: SV-26444r1 - The /etc/gshadow file must must have mode 0400
# Change /etc/gshadow to 0400.  OOB is 0640.
#

if os.path.exists("/etc/gshadow"):
    gsmod = os.system('stat -L --format=\'%04a\' /etc/gshadow')
    if gsmod != "0400":
        print '/etc/gshadow file mod changed to 0400.\n'
        os.system('chmod u+r,u-wxs,g-rwxs,o-rwxt /etc/gshadow')
    else:
        print '/etc/gshadow file mod is already 0400.\n'
else:
    print '/etc/gshadow does not exist.\n'

#
# Rule Id: SV-1015r7 - The ext3 filesystem type must be used for primary Linux
# file system partitions.  Check to see if /etc/fstab lists any ext1 or ext2 for
# listed active partitions.
#
# The script cannot fix the problem.  It only notes this as a CATII failure that
# must be fixed separately.
#

with open("/etc/fstab", "r") as fstab_file:
    lines = fstab_file.readlines()
    fstab_file.seek(0)
    count = 0
    for line in lines:
        pos_1 = line[0]
        if pos_1 == '#': continue
        elif 'ext1' in line:
            print '/etc/fstab contains an ext1 file system.  CATII failure.\n'
        elif 'ext2' in line:
            print '/etc/fstab contains an ext2 file system.  CATII failure.\n'
        else: continue

#
# Rule Id: SV-1055r5 - The /etc/security/access.conf file must have mode 0640 or less
# Change from 0644 to 0640.
#

if os.path.exists("/etc/security/access.conf"):
    acmod = os.system('stat -L --format=\'%04a\' /etc/security/access.conf')
    if acmod != "0640":
        print '/etc/security/access.conf file mod changed to 0640.\n'
        os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/security/access.conf')
    else:
        print '/etc/security/access.conf file mod is already 0640.\n'
else:
    print '/etc/security/access.conf does not exist.\n'

#
# Rule Id: SV-4336r5 - The /etc/sysctl.conf file must have mode 0600 or less
# Change from 0644 to 0600.
#

if os.path.exists("/etc/sysctl.conf"):
    scmod = os.system('stat -L --format=\'%04a\' /etc/sysctl.conf')
    if scmod != "0600":
        print '/etc/security/access.conf file mod changed to 0600.\n'
        os.system('chmod u+rw,u-xs,g-rwxs,o-rwxt /etc/sysctl.conf')
    else:
        print '/etc/sysctl.conf file mod is already 0600.\n'
else:
    print '/etc/sysctl.conf does not exist.\n'

#
# Rule Id: SV-12541r2 - The /etc/securetty file must have mode 0640 or less
# Change from 0644 to 0640.
#

if os.path.exists("/etc/securetty"):
    stymod = os.system('stat -L --format=\'%04a\' /etc/sysctl.conf')
    if stymod != "0640":
        print '/etc/securetty file mode changed to 0640.\n'
        os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/sysctl.conf')
    else:
        print '/etc/securetty file mod is already 0640.\n'
else:
    print '/etc/securetty does not exist.\n'

#
# Rule Id: SV-27059r1 - Vendor-recommended software patches and updates, and
# system security patches and updates, must be installed and up-to-date.
#

with open("/etc/apt/apt.conf.d/10periodic", "r+") as periodic_file:
    periodic_file.seek(0)
    periodic_file.truncate()
    periodic_file.write("APT::Periodic::Update-Package-Lists \"1\";\n")
    periodic_file.write("APT::Periodic::Download-Upgradeable-Packages \"1\";\n")
    periodic_file.write("APT::Periodic::AutocleanInterval \"7\";\n")
    periodic_file.write("APT::Periodic::Unattended-Upgrade \"1\";\n")
periodic_file.close()
print 'Vendor upgrades set to automatic.\n'

#
# Rule Id: SV-26307r1_rule
# Rule Title: The system time synchronization method must use cryptographic algorithms to verify 
# the authenticity and integrity of the time data.
#
# OOB Ubuntu does not have this configured.  This will be noted as a failure in the check log only.
# No separate configuration check will be done.
#

print 'CATII SV-12442-1r6 Failure. NTP not configured to use cryptographic algorithms to verify the authenticity and integrity of the time data.\n'

#
# Rule Id: SV-26297r1_rule
# Rule Title: The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.
#

if os.path.exists("/etc/ntp.conf"):
    ntpconfmod = os.system('stat -L --format=\'%04a\' /etc/ntp.conf')
    if ntpconfmod != "0640":
        os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/ntp.conf')
        print '/etc/ntp.conf file mode changed to 0640.\n'
    else:
        print '/etc/ntp.conf file mod is already 0640.\n'
else:
    print 'SV-26297r1 CATII Failure /etc/ntp.conf does not exist.\n'

#
#Rule Id: SV-4269-1r4_rule
#Rule Title: The system must not have the unnecessary games account.
#
# Checks for user games and removes the user and group games if user games is
# found.  Group is also removed by the system since it is only associated with the user
# games and not required by the system otherwise.
#

games_user_check=os.system('grep ^games /etc/passwd')
if games_user_check == 0:
    os.system('deluser --remove-home --remove-all-files games')
    print 'User games and group games removed from system.\n'
else:
    print 'User games not found.\n'

#
# Rule Id: SV-4269-2r4_rule
# Rule Title: The system must not have the unnecessary news account.
#
# Checks for user news and removes the user and group news if user news is
# found.  Group is also removed by the system since it is only associated with the user
# news and not required by the system otherwise.
#

news_user_check=os.system('grep ^news /etc/passwd')
if news_user_check == 0:
    os.system('deluser --remove-home --remove-all-files news')
    print 'User news and group news removed from system.\n'
else:
    print 'User news not found.\n'

#
# Rule Id: SV-4269-2r4_rule
# Rule Title: The system must not have the unnecessary lp account.
#
# Checks for user lp and removes the user and group lp if user lp is
# found.  Group is also removed by the system since it is only associated with the user
# lp and not required by the system otherwise.
#

lp_user_check=os.system('grep ^news /etc/passwd')
if lp_user_check == 0:
    os.system('deluser --remove-home --remove-all-files lp')
    print 'User lp and group lp removed from system.\n'
else:
    print 'User lp not found.\n'

#
# Rule Id: SV-27090r1_rule - The system must disable accounts after three consecutive 
# unsuccessful login attempts.  This sets the level in the /etc/pam.d/common-auth file.
#

with open("/etc/pam.d/common-auth", "r+") as com_auth_file:
    lines = com_auth_file.readlines()
    com_auth_file.seek(0)
    com_auth_file.truncate()
    for line in lines:
        if "# pam-auth-update(8) for details" in line:
            com_auth_file.write(line) 
            com_auth_file.write("\n")
            com_auth_file.write("auth required pam_tally.so per_user magic_root deny=3 lock_time=4 onerr=fail\n")
            com_auth_file.write("\n")
        else:
            com_auth_file.write(line)
com_auth_file.close()

#
# Addresses Rule Id's: SV-27101r1_rule and SV-27129r1_rule - Cannot change password more than once a day,
# and must be changed every 60 days.
#

with open("/etc/login.defs", "r+") as logdefs_file:
    lines = logdefs_file.readlines()
    logdefs_file.seek(0)
    logdefs_file.truncate()
    count=0
    for line in lines:
        if count == 0 and "# Password aging controls" in line:
            logdefs_file.write(line)
            logdefs_file.write("#\n")
            logdefs_file.write("\n")
            logdefs_file.write("PASS_MAX_DAYS   60\n")
            logdefs_file.write("PASS_MIN_DAYS   1\n")
            logdefs_file.write("PASS_WARN_AGE   7\n")
            logdefs_file.write("\n")
            count=1
        elif count == 1 and "PASS_" in line: continue
        elif count == 1 and "max values for automatic uid selection in useradd" in line:
            logdefs_file.write("#\n")
            logdefs_file.write(line)
            count=2
        elif count == 1 and "\n" in line: continue
        else:
            logdefs_file.write(line)
logdefs_file.close()

#
# Rule Id: SV-27114r1_rule, SV-26321r1_rule, SV-27122r1_rule, SV-27125r1_rule, SV-27128r1_rule, SV-26323r1_rule,
# SV-26344r1_rule, Must have four character changes between old and new password, 
# at least one lowercase alphabetic character, at least one numeric character, at least one special character, 
# no more than three consecutive repeating characters and at least four characters changed between the old and new password.
#

with open("/etc/pam.d/common-password", "r+") as comm_pass_file:
    lines = comm_pass_file.readlines()
    comm_pass_file.seek(0)
    comm_pass_file.truncate()
    count = 0
    for line in lines:
        if count == 0 and "# here are the per-package modules" in line:
            comm_pass_file.write(line)
            comm_pass_file.write("password        requisite                       pam_cracklib.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 difok=4\n")
            comm_pass_file.write("password        [success=1 default=ignore]      pam_unix.so obscure remember=5 use_authtok try_first_pass sha512\n")
            count=1
        elif count == 1 and "password " in line: continue
        elif count == 1 and "# here's the fallback if no module succeeds" in line:
            comm_pass_file.write(line)
            count=2
        else:
            comm_pass_file.write(line)
comm_pass_file.close()

#
# Rule Id: SV-27146r1_rule.  The system must prevent the root account from directly logging in except from the system console.  
# This removes console login from /etc/securetty.
#

with open("/etc/securetty", "r+") as securetty_file:
    lines = securetty_file.readlines()
    securetty_file.seek(0)
    securetty_file.truncate()
    for line in lines:
        if "#" not in line and line.strip() != "":
            comment_line="#" + line
            securetty_file.write(comment_line)
        else:
            securetty_file.write(line)
securetty_file.close()

#
# Rule Id: SV-1047r7_rule. The system must not permit root logins using remote access programs such as ssh.
#

with open("/etc/ssh/sshd_config", "r+") as sshd_conf_file:
    lines = sshd_conf_file.readlines()
    sshd_conf_file.seek(0)
    sshd_conf_file.truncate()
    for line in lines:
        if "#" not in line and "PermitRootLogin" in line:
            sshd_conf_file.write("PermitRootLogin no\n")
        else:
            sshd_conf_file.write(line)
sshd_conf_file.close()

#
# Rule Id: SV-787r9_rule. System log files must have mode 0640 or less permissive.
# Changes /var/log mod from 0755 to 0640
#

os.system('chmod 0640 /var/log')

#
# Rule Id: SV-800r7_rule. All global initialization files must have mode 0644 or less permissive.
# Changes file permissions to 0644
#

os.system('chmod 0644 /etc/shadow')

#
# SV-12482r4_rule. The /etc/shadow (or equivalent) file must have mode 0400.
# Changes /etc/shadow mod from 0640 to 0400
#

os.system('chmod 0640 /etc/profile.d/rvm.sh /etc/security /etc/security/limits.d /etc/security/namespace.d /etc/security/namespace.init')

#
# Addresses Rule Id's: SV-905r6_rule - All local initialization files must have mode 0740 or less permissive.
# Right now this is just a hack for the vagrant user settings, the only "user" on the box.
#

with open("/etc/login.defs", "r+") as umask_file:
    lines = umask_file.readlines()
    umask_file.seek(0)
    umask_file.truncate()
    for line in lines:
        if "# " not in line and "UMASK" in line:
            umask_file.write("UMASK           077\n")
        else:
            umask_file.write(line)
umask_file.close()

os.system('find /home/vagrant -maxdepth 1 -name \'.*\' -type f -exec chmod 740 {} +')

#
# Addresses Rule Id's: SV-924r6_rule - Device files and directories must only be writable by users with a system account or as
# configured by the vendor.  See notes for the devices not changed.
#

os.system('chmod 660 /dev/ptmx /dev/urandom /dev/tty /dev/random /dev/full')

#
# Tripwire configuration
#
# SV-803r7_rule - The system must be checked weekly for unauthorized setuid files as well as unauthorized modification to 
# authorized setuid files.
#
# First find all the SUID and GUID files on the system and exclude and not founds. Add them to the tripwire policy file.
#
# Build a weekly cron job to check if there are any diffs and notify the admin user.
#

# Find all the SUID and GUID and put in file to parse through.  This is done as a command to account for system install variations.

os.system('find / -type f -perm -2000 -print > /var/log/sgid-file-list;chmod 0600 /var/log/sgid-file-list;chown root:root /var/log/sgid-file-list;')
os.system('find / -type f -perm -4000 -print > /var/log/suid-file-list;chmod 0600 /var/log/suid-file-list;chown root:root /var/log/suid-file-list;')

# Modify the tripwire policy file and add the SUID and GUID checks

with open("/etc/tripwire/twpol.txt", "a") as twpol_file:
    with open("/var/log/suid-file-list", "r") as SUID_file:
        SUID_file.seek(0)
        twpol_file.write("#\n")
        twpol_file.write("# SUID files\n")
        twpol_file.write("#\n")
        twpol_file.write("(\n")
        twpol_file.write("  rulename = \"SUID Files\",\n")
        twpol_file.write("  severity = $(SIG_HI),\n")
        twpol_file.write(")\n")
        twpol_file.write("{\n")
        lines = SUID_file.readlines()
        for line in lines:
            string = line.strip('\n')
            string2 = "        " + string + " -> $(SEC_BIN) ;\n"
            twpol_file.write(string2)
        twpol_file.write("}\n")
        twpol_file.write("\n")
    SUID_file.close()

    with open("/var/log/sgid-file-list", "r") as SGID_file:
        SGID_file.seek(0)
        twpol_file.write("#\n")
        twpol_file.write("# SGID files\n")
        twpol_file.write("#\n")
        twpol_file.write("(\n")
        twpol_file.write("  rulename = \"SGID Files\",\n")
        twpol_file.write("  severity = $(SIG_HI),\n")
        twpol_file.write(")\n")
        twpol_file.write("{\n")
        lines = SGID_file.readlines()
        for line in lines:
            string = line.strip('\n')
            string2 = "        " + string + " -> $(SEC_BIN) ;\n"
            twpol_file.write(string2)
        twpol_file.write("}\n")
        twpol_file.write("\n")
    SGID_file.close()
twpol_file.close()

# add the admin email for every rulename

with open("/etc/tripwire/twpol.txt", "r+") as twpol2_file:
    lines = twpol2_file.readlines()
    twpol2_file.seek(0)
    twpol2_file.truncate()
    for line in lines:
        if "severity" in line:
            twpol2_file.write(line)
            twpol2_file.write("  emailto = %s\n" %str(admin1))
        else:
            twpol2_file.write(line)
twpol2_file.close()

# Update the Tripwire policy

os.system('twadmin --create-polfile /etc/tripwire/twpol.txt')

# Add weekly cron jobs to check if there are unauthorized setuid files or unauthorized modification to
# authorized setuid files
os.system('cp ./doc/sgid-files-check /etc/cron.weekly;chmod 700 /etc/cron.weekly/sgid-files-check;chown root:root /etc/cron.weekly/sgid-files-check;')
os.system('cp ./doc/suid-files-check /etc/cron.weekly;chmod 700 /etc/cron.weekly/suid-files-check;chown root:root /etc/cron.weekly/suid-files-check;')

#
# SV-27320r1_rule - Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).
#
# This script creates a cron.allow and adds root as the only user.
#

os.system('touch /etc/cron.allow')
os.system('echo "root" > /etc/cron.allow')
os.system('chmod 0600 /etc/cron.allow')
os.system('chown root:root /etc/cron.allow')

#
# SV-27341r1_rule and SV-27344r1_rule - Cron file permission mode <= 0700, cron directory <= 755.
#

os.system('find /etc/cron* -type f | xargs chmod 700')
os.system('find /var/spool/cron* -type f | xargs chmod 700')
os.system('find /etc/cron* -type d | xargs chmod 755')
os.system('find /var/spool/cron* -type d | xargs chmod 755')

#
# SV-27352r1_rule - Cron logging must be implemented.
#


with open("/etc/rsyslog.d/50-default.conf", "r+") as cron_log_file:
    lines = cron_log_file.readlines()
    cron_log_file.seek(0)
    cron_log_file.truncate()
    for line in lines:
        if "#" in line and "/var/log/cron.log" in line:
            cron_log_file.write('cron.*                          /var/log/cron.log\n')
        else:
            cron_log_file.write(line)
cron_log_file.close()

#
# SV-27357r1_rule - The cronlog file must have mode 0600 or less permissive.
#

os.system('touch /var/log/cron.log')
os.system('find /var/log/cron.log -perm /7177 -exec chmod u-xs,g-rwxs,o-rwxt {} \;')

#
# SV-27379r1_rule - Access to the "at" utility must be controlled via the at.allow and/or at.deny file(s).
#
# This script creates a at.allow and adds root as the only user.
#

os.system('touch /etc/at.allow')
os.system('echo "root" > /etc/at.allow')
os.system('chmod 0600 /etc/cron.allow')
os.system('chown root:root /etc/at.allow')

#
# SV-4364r7_rule - The "at" directory must have mode 0755 or less permissive.
# SV-4365r7_rule - The "at" directory must be owned by root, bin, or sys.
#

os.system('chmod 0700 /var/spool/cron/atjobs')
os.system('chown root:root /var/spool/cron/atjobs')

#
# SV-26572r1_rule - The at.deny file must be group-owned by root, bin, sys, or cron.
#

os.system('chown root:root /etc/at.deny')

#
# SV-29290r1_rule - The system must not apply reversed source routing to TCP responses.
# SV-26629r1_rule - The system must ignore IPv4 ICMP redirect messages.
# SV-29795r1_rule - The system must not forward IPv4 source-routed packets.
# SV-26216r1_rule - The IPv6 protocol handler must not be bound to the network stack unless needed.
# SV-26919r1_rule - The IPv6 protocol handler must be prevented from dynamic loading unless needed.
# SV-26935r1_rule - The system must ignore IPv6 ICMP redirect messages.
# SV-26228r1_rule - The system must not forward IPv6 source-routed packets.
#
# Changes the settings in the sysctl.conf

with open("/etc/sysctl.conf", "a") as sysctl_file:
    sysctl_file.write("\n")
    sysctl_file.write("#\n")
    sysctl_file.write("# Disable STIG IP source routing\n\n")
    sysctl_file.write("net.ipv4.conf.lo.accept_source_route = 0\n")
    sysctl_file.write("net.ipv4.conf.eth0.accept_source_route = 0\n")
    sysctl_file.write("net.ipv4.conf.all.accept_source_route = 0\n")
    sysctl_file.write("net.ipv4.conf.default.accept_source_route = 0\n")
    sysctl_file.write("net.ipv4.conf.all.accept_redirects = 0\n")
    sysctl_file.write("net.ipv4.conf.all.send_redirects = 0\n")
    sysctl_file.write("\n")
    sysctl_file.write("#\n")
    sysctl_file.write("# Disable IPV6\n\n")
    sysctl_file.write("#\n")
    sysctl_file.write("\n")
    sysctl_file.write("net.ipv6.conf.all.disable_ipv6 = 1\n")
    sysctl_file.write("net.ipv6.conf.default.disable_ipv6 = 1\n")
    sysctl_file.write("net.ipv6.conf.lo.disable_ipv6 = 1\n")
    sysctl_file.write("net.ipv6.conf.default.accept_redirects = 0\n")
    sysctl_file.write("net.ipv6.conf.all.accept_redirects = 0\n")
    sysctl_file.write("net.ipv6.conf.all.forwarding = 0\n")
    sysctl_file.write("net.ipv6.conf.default.forwarding = 0\n")
sysctl_file.close()

os.system('echo "#" >> /etc/modprobe.d/blacklist.conf')
os.system('echo "blacklist ipv6" >> /etc/modprobe.d/blacklist.conf')

#
# SV-12507r6_rule - The SMTP service HELP command must not be enabled
#
# This will zero out the help file thus providing no information.
#

with open("/etc/mail/helpfile", "r+") as mailhelp_file:
    lines = mailhelp_file.readlines()
    mailhelp_file.seek(0)
    mailhelp_file.truncate()
    mailhelp_file.write("\n")
mailhelp_file.close()

#
# SV-28408r1_rule - The ftpusers file must contain account names not allowed to use FTP.
# SV-28405r1_rule - The ftpusers file must exist
# This will zero out the help file thus providing no information.
#

os.system('touch /etc/ftpusers')
os.system('chmod 0640 /etc/ftpusers')
os.system('echo "#" > /etc/ftpusers')

#
# SV-26740r1_rule - The /etc/syslog.conf (rsyslog.conf for Ubuntu) file must have mode 0640 or less permissive.
#

os.system('chmod 0640 /etc/rsyslog.conf')

#
# SV-26749r1_rule - The SSH client must be configured to only use the SSHv2 protocol.
# SV-28763r1_rule - The SSH client must use a FIPS 140-2 validated cryptographic module.
# SV-26754r1_rule - The SSH client must be configured to only use FIPS 140-2 approved ciphers.
# SV-26755r1_rule - The SSH client must be configured to not use CBC-based ciphers.
# SV-26756r1_rule - The SSH client must be configured to only use MACs that employ FIPS 140-2 approved cryptographic hash algorithms.
#
with open("/etc/ssh/ssh_config", "r+") as ssh_config_file:
    lines = ssh_config_file.readlines()
    ssh_config_file.seek(0)
    ssh_config_file.truncate()
    for line in lines:
        if "Protocol 2,1" in line:
            ssh_config_file.write(line)
            ssh_config_file.write("Protocol 2\n")
        elif "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc" in line:
            ssh_config_file.write(line)
            ssh_config_file.write("Ciphers aes128-ctr,aes192-ctr,aes256-ctr\n")
        elif "MACs hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160" in line:
            ssh_config_file.write(line)
            ssh_config_file.write("MACs hmac-sha1\n")
        elif "Tunnel no" in line:
            ssh_config_file.write(line)
            ssh_config_file.write("Tunnel no\n")
        else:
            ssh_config_file.write(line)
ssh_config_file.close()

#
# SV-28762r1_rule - The SSH daemon must use a FIPS 140-2 validated cryptographic module.
# SV-26753r1_rule - The SSH daemon must be configured to only use MACs that employ FIPS 140-2 approved cryptographic hash algorithms.
# SV-26752r1_rule - The SSH daemon must be configured to not use CBC ciphers.
# SV-26751r1_rule - The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.
#

with open("/etc/ssh/sshd_config", "r+") as sshd_config_file:
    lines = sshd_config_file.readlines()
    sshd_config_file.seek(0)
    sshd_config_file.truncate()
    for line in lines:
        if "ChallengeResponseAuthentication" in line:
            sshd_config_file.write(line)
            sshd_config_file.write("\n")
            sshd_config_file.write("# Ciphers List\n")
            sshd_config_file.write("Ciphers aes128-ctr,aes192-ctr,aes256-ctr\n")
            sshd_config_file.write("\n")
            sshd_config_file.write("# MACs List\n")
            sshd_config_file.write("MACs hmac-sha1\n")
            sshd_config_file.write("\n")
            sshd_config_file.write("# Allow group sudo to ssh in\n")
            sshd_config_file.write("#AllowGroups sudo\n")
            sshd_config_file.write("\n")
            sshd_config_file.write("# Deny user sh login\n")
            sshd_config_file.write("#DenyUsers\n")
            sshd_config_file.write("\n")
            sshd_config_file.write("# Permit Tunnels\n")
            sshd_config_file.write("PermitTunnel no\n")
            sshd_config_file.write("\n")
            sshd_config_file.write("# Compression after authentication\n")
            sshd_config_file.write("Compression delayed\n")
            sshd_config_file.write("\n")
        elif "UseDNS" in line:
            sshd_config_file.write("#UseDNS no\n")
        else:
            sshd_config_file.write(line)
sshd_config_file.close()

#
# SV-782r7_rule - The system must have a host-based intrusion detection tool installed.
# SV-12529r3_rule - The system vulnerability assessment tool, host-based intrusion detection 
# tool, and file integrity tool must notify the SA and the IAO of a security breach or a suspected 
# security breach. For SNORT snort.debian.conf will be reset to admin.
#

os.system('apt-get install snort')

with open("/etc/snort/snort.debian.conf", "r+") as snort_conf_file:
    lines = snort_conf_file.readlines()
    snort_conf_file.seek(0)
    for line in lines:
        if 'DEBIAN_SNORT_STATS_RCPT' in line:
            snort_conf_file.write("DEBIAN_SNORT_STATS_RCPT=\"%s\"\n" %str(admin1))
        else:
            snort_conf_file.write(line)
snort_conf_file.close()

#
# SV-28462r1_rule - The system must use and update a DoD-approved virus scan program. Open source AV installed.
# Sites can reconfigure as appropriate.
# SV-12529r3_rule - Add rule to scan once a week and email admin account.
#

os.system('apt-get install clamav-freshclam')

with open("/etc/cron.weekly/clamav", "w+") as clamav_file:
    clamav_file.write("#!/bin/sh\n")
    clamav_file.write("\n")
    clamav_file.write("# scan the whole system, disregarding errors\n")
    clamav_file.write("clamscan -ri / 2>/dev/null | sendmail %s\n" % str(admin1))
clamav_file.close()

#
# Roothunter install and configuration.
#

os.system('apt-get install rkhunter')

with open("/etc/default/rkhunter", "r+") as rkhunter_file:
    lines = rkhunter_file.readlines()
    rkhunter_file.seek(0)
    for line in lines:
        if 'CRON_DAILY_RUN' in line:
            rkhunter_file.write("CRON_DAILY_RUN=\"yes\"\n")
        elif 'CRON_DB_UPDATE' in line:
            rkhunter_file.write("CRON_DB_UPDATE=\"yes\"\n")
        elif 'REPORT_EMAIL' in line:
            rkhunter_file.write("REPORT_EMAIL=\"%s\"\n" %str(admin1))
        else:
            rkhunter_file.write(line)
rkhunter_file.close()

#
# Chkrootkit install and configuration.
# SV-12529r3_rule - The system vulnerability assessment tool, host-based intrusion detection tool, 
# and file integrity tool must notify the SA and the IAO of a security breach or a suspected security breach.
# SV-26250r1_rule - A root kit check tool must be run on the system at least weekly.
#

os.system('apt-get install chkrootkit')

with open("/etc/cron.daily/chkrootkit", "r+") as chkrootkit_file:
    lines = chkrootkit_file.readlines()
    chkrootkit_file.seek(0)
    for line in lines:
        if 'eval $CHKROOTKIT $RUN_DAILY_OPTS' in line:
            chkrootkit_file.write("eval $CHKROOTKIT $RUN_DAILY_OPTS | sendmail %s\n" % str(admin1))
        else:
            chkrootkit_file.write(line)
chkrootkit_file.close()

with open("/etc/chkrootkit.conf", "r+") as chkrootkit_conf_file:
    lines = chkrootkit_conf_file.readlines()
    chkrootkit_conf_file.seek(0)
    for line in lines:
        if 'RUN_DAILY=' in line: 
            chkrootkit_conf_file.write("RUN_DAILY=\"true\"\n")
        else:
            chkrootkit_conf_file.write(line)
chkrootkit_conf_file.close()

#
# SV-26856r1_rule - The system package management tool must be used to verify system software periodically.
# dbsums package installed and configured.
#

os.system('apt-get install debsums')

with open("/etc/default/debsums", "r+") as debsums_file:
    lines = debsums_file.readlines()
    debsums_file.seek(0)
    for line in lines:
        if 'CRON_CHECK=' in line: 
            debsums_file.write("CRON_CHECK=weekly\n")
        else:
            debsums_file.write(line)
debsums_file.close()

#
# SV-29414r1_rule - 
#
# uncomment if going to implement the ldd restriction.

os.system('chmod a-x /usr/bin/ldd')

#
# iptable fixes
#
# SV-26192r1_rule - UDP-Lite disabled 
# SV-26887r1_rule - AppleTook disabled
#

with open("/etc/services", "r+") as ipx_file:
    lines = ipx_file.readlines()
    ipx_file.seek(0)
    ipx_file.truncate()
    for line in lines:
        if "ipx" in line:
            line = "# " + line
            ipx_file.write(line)
        elif "AppleTalk" in line:
            line = "# " + line
            ipx_file.write(line)
        else:
            ipx_file.write(line)
ipx_file.close()

#
# add iptable rules
# SV-26973r1_rule - The system must employ a local firewall
# SV-26975r1_rule - The system's local firewall must implement a deny-all, allow-by-exception policy.
# SV-26192r1_rule - The Lightweight User Datagram Protocol (UDP-Lite) must be disabled unless required.
#
# Script added to root home directory

os.system('cp ./doc/iptables.sh /root;chmod 700 /root/iptables.sh')
os.system('cp ./doc/save-then-clear-iptables.sh /root;chmod 700 /root/save-then-clear-iptables.sh')

#
# SV-4250r5_rule - The system's boot loader configuration file(s) must have mode 0600 or less permissive.
#
# File is 0444.  Setting to 0400.
#

os.system('chmod 0400 /boot/grub/grub.cfg') 

#########################################################################################################################
#
# Other fixes
#
# The following cleans up any other identified security issues not identified with the STIGs.  The STIGs used to
# conduct the checks are based on RedHat.  There are some Ubuntu unique issues that may not be addressed by the RedHat STIG.
# Those findings are fixed here.
#
#########################################################################################################################

# The following removes the Ubuntu package "popularity contest".  This is a package that is installed by default with
# Ubuntu and it sends a list of packages used by a system daily to a server. The default installation is set to "no"
# in the /etc/popularity-contest.config, so the package does not run, but the package has the potential to send information
# about a server, such as what is running, security packages, etc, so it is removed.

os.system('apt-get --purge remove popularity-contest')

# Remove the games directories. The games account was deleted but games directories exist.

os.system('rm -R /usr/local/games;rm -R /usr/games')

