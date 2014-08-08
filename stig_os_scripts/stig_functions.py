#########################################################################################################################
# STIG OS functions for Ubuntu 12.04 called by the main script. 
#
# JAM
# LMN Solutions
# Version 0.99
# 29 April 2014
#########################################################################################################################

# Load the imports required by the script.
import os
import os.path
import subprocess
import stat
import getpass

# Check the OS version first.  Meets a STIG requirement and if it's not a supported version for this lockdown script exit
#
# Rule-ID SV-27049r1 - OS must be a supported release
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

if (os_text_version != "12.03") and (os_text_version != "12.04") and (os_text_version != "12.04.4"):
    print 'Unsupported version of Ubuntu detected.\nThis script supports Ubuntu 12.03 LTS and 12.04 LTS.\nExiting.\n'
    exit()

#
# Do a package update to get the latest package indexes.  Some packages will fail if this is not done.
#

os.system('apt-get update')

# Install python-pexpect since it is required by the script.

# Check if installed. If not, install it.
#

pexpect_check=os.system('dpkg --get-selections | grep pexpect')

if pexpect_check != 0:
    os.system('apt-get install -y python-pexpect')
    import pexpect
else:
    import pexpect

#########################################################################################################################
#
# Install any of the necessary packages for the system lockdown.  Install upfront since CAT changes are not always in
# order. Any STIG required configuration will also be done as part of the install
#
#########################################################################################################################

#
# The checks ascertain if a particular STIG OS CAT has been applied.  If found it assumes reconfiguration is not needed.
# If not found it applies the particular lockdown.
# This is a conscious decision for a desire not to make this an admin check script but rather a STIG lockdown for an initial
# OS lockdown or system reprovision.
#

def audit():

    #
    # SV-27270r1_rule. Auditing must be implemented.
    #
    # This script is upfront to allow for changes to the /etc/pam.d/common-auth changes that will be implemented for STIGs
    # later in the script.
    #

    # install auditd

    auditd_check=os.system('dpkg --get-selections | grep auditd')
    if auditd_check != 0:
        print 'Installing auditing.\n'
        os.system('apt-get install -y auditd')
        # rotate the logs daily
        print 'Configuring auditing.\n'
        os.system('cp ./doc/auditd /etc/cron.daily;chmod 700 /etc/cron.daily/auditd;chown root:root /etc/cron.daily/auditd')
    else:
        print 'auditd already installed.\n'

def ntp_server():

    #
    # Ran into an instance where ntp was not installed as part of the Ubuntu. 
    # If ntp server isn't installed, install it for later STIG required configuration.
    #

    ntp_check=os.system('dpkg --get-selections | grep \'\<ntp\>\'')
    if ntp_check != 0:
        print 'Installing ntp server.\n'
        os.system('apt-get install -y ntp')
    else:
        print 'ntp is already installed.\n'

def tripwire(admin1):
    #
    # Rule Id: SV-12442-1r6
    # Rule Title: A file integrity baseline must be created.
    #
    # The following installs tripwire and initiates the baseline if tripwire install not found

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

    trip_check=os.system('dpkg --get-selections | grep tripwire')
    if trip_check != 0:
        print 'Installing tripwire.\n'
        os.system('apt-get install -y tripwire && tripwire --init')
        # Find all the SUID and GUID and put in file to parse through.  This is done as a command to account for system install variations.
        print 'Configuring tripwire.\n'
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
    else:
        print 'tripwire already installed.\n'

def mail():
    print 'Installing mail and postfix.\n'
    #
    # Sendmail  and postfix - not spelled out in the STIGs per say but is necessary to send administrator email in a number of 
    # the STIG changes.
    #

    sendmail_check=os.system('dpkg --get-selections | grep sendmail')
    postfix_check=os.system('dpkg --get-selections | grep sendmail')
    if sendmail_check != 0:
        print 'Installing sendmail.\n'
        os.system('apt-get install -y sendmail')
    if postfix_check != 0:
        print 'Installing postfix.\n'
        os.system('apt-get install -y postfix')
    else:
        print 'sendmail and postfix already installed.\n'

def snort(admin1):
    #
    # SV-782r7_rule - The system must have a host-based intrusion detection tool installed.
    # SV-12529r3_rule - The system vulnerability assessment tool, host-based intrusion detection 
    # tool, and file integrity tool must notify the SA and the IAO of a security breach or a suspected 
    # security breach. For SNORT snort.debian.conf will be reset to admin.
    #

    snort_check=os.system('dpkg --get-selections | grep snort')
    if snort_check != 0:
        print 'Installing snort.\n'
        os.system('apt-get install -y snort')
        print 'Configuring snort.\n'
        with open("/etc/snort/snort.debian.conf", "r+") as snort_conf_file:
            lines = snort_conf_file.readlines()
            snort_conf_file.seek(0)
            for line in lines:
                if 'DEBIAN_SNORT_STATS_RCPT' in line:
                    snort_conf_file.write("DEBIAN_SNORT_STATS_RCPT=\"%s\"\n" %str(admin1))
                else:
                    snort_conf_file.write(line)
        snort_conf_file.close()
    else:
        print 'snort already installed.\n'

def clamav(admin1):
    #
    # SV-28462r1_rule - The system must use and update a DoD-approved virus scan program. Open source AV installed.
    # Sites can reconfigure as appropriate.
    # SV-12529r3_rule - Add rule to scan once a week and email admin account.
    #

    clamav_check=os.system('dpkg --get-selections | grep clamav')
    if clamav_check != 0:
        print 'Installing Clam AntiVurus.\n'
        os.system('apt-get install -y clamav-freshclam')
        print 'Configuring Clamav.\n'
        os.system('freshclam')
        with open("/etc/cron.weekly/clamav", "w+") as clamav_file:
            clamav_file.write("#!/bin/sh\n")
            clamav_file.write("\n")
            clamav_file.write("# scan the whole system, disregarding errors\n")
            clamav_file.write("clamscan -ri / 2>/dev/null | sendmail %s\n" % str(admin1))
        clamav_file.close()
    else:
        print 'Clam AV already installed.\n'

def rkhunter(admin1):
    #
    # Roothunter install and configuration.
    #

    rkhunter_check=os.system('dpkg --get-selections | grep rkhunter')
    if rkhunter_check != 0:
        print 'Installing rkhunter.\n'
        os.system('apt-get install -y rkhunter')
        print 'Configuring rkhunter.\n'
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
    else:
        print 'rkhunter already installed.\n'

def chkrootkit(admin1):
    #
    # Chkrootkit install and configuration.
    # SV-12529r3_rule - The system vulnerability assessment tool, host-based intrusion detection tool, 
    # and file integrity tool must notify the SA and the IAO of a security breach or a suspected security breach.
    # SV-26250r1_rule - A root kit check tool must be run on the system at least weekly.
    #

    chkrootkit_check=os.system('dpkg --get-selections | grep chkrootkit')
    if chkrootkit_check != 0:
        print 'Installing chkrootkit.\n'
        os.system('apt-get install -y chkrootkit')
        print 'Configuring chkrootkit.\n'
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
    else:
        print 'chkrootkit already installed.\n'

def debsums():
    #
    # SV-26856r1_rule - The system package management tool must be used to verify system software periodically.
    # debsums package installed and configured.
    #

    debsums_check=os.system('dpkg --get-selections | grep debsums')
    if debsums_check != 0:
        print 'Installing debsums.\n'
        os.system('apt-get install -y debsums')
    else:
        print 'debsums already installed.\n'

    if "CRON_CHECK=weekly" not in open('/etc/default/debsums').read():
        print 'Configuring debsums.\n'
        with open("/etc/default/debsums", "r+") as debsums_file:
            lines = debsums_file.readlines()
            debsums_file.seek(0)
            for line in lines:
                if 'CRON_CHECK=' in line: 
                    debsums_file.write("CRON_CHECK=weekly\n")
                else:
                    debsums_file.write(line)
        debsums_file.close()
    else:
        print 'debsums already configured.\n'

#########################################################################################################################
#
# Purge STIG identified packages.  Purge up front so that not being done off and on during the installation.
#
#########################################################################################################################

def rpcbind():
    #
    # SV-26666r1_rule - The portmap or rpcbind service must not be installed unless needed.
    #
    # Removes rpcbind and portmap
    #

    rpcbind_check=os.system('dpkg --get-selections | grep rpcbind')
    if rpcbind_check == 0:
        print 'Purging dbsums.\n'
        os.system('apt-get purge -y rpcbind')
    else:
        print 'rpcbind not installed.\n'

def tpcdump():
    #
    # SV-12550r5_rule - Network analysis tools must not be installed
    #
    # Removes tcpdump and mitigates nc.openbsd
    #

    tpcdump_check=os.system('dpkg --get-selections | grep tcpdump')
    if tpcdump_check == 0:
        print 'Purging tpcdump and nullifying openbsb.\n'
        os.system('apt-get purge -y tcpdump')
        os.system('chmod 0000 /bin/nc.openbsd')
    else:
        print 'tpcdump not installed.\n'
        print 'openbsb nullified.\n'
        os.system('chmod 0000 /bin/nc.openbsd')

def popularity():
    # The following removes the Ubuntu package "popularity contest".  This is a package that is installed by default with
    # Ubuntu and it sends a list of packages used by a system daily to a server. The default installation is set to "no"
    # in the /etc/popularity-contest.config, so the package does not run, but the package has the potential to send information
    # about a server, such as what is running, security packages, etc, so it is removed.

    popularity_check=os.system('dpkg --get-selections | grep popularity-contest')
    if popularity_check == 0:
        print 'Purging popularity-contest.\n'
        os.system('apt-get --purge -y remove popularity-contest')
    else:
        print 'popularity-contest not installed.\n'


#########################################################################################################################
#
# Start CAT I Lockdown
#
#########################################################################################################################

def SV4268r5():
    #
    # Rule Id: SV-4268r5 - No special privilege accounts
    #
    # If found, some of these accounts will be deleted.  Others will post a warning for additional verification.
    
    SV_shutdown = os.system('grep "shutdown" /etc/passwd /etc/shadow')
    SV_halt = os.system('grep "halt" /etc/passwd /etc/shadow')
    SV_reboot = os.system('grep "reboot" /etc/passwd /etc/shadow')
    SV_vagrant = os.system('grep "vagrant" /etc/passwd /etc/shadow')
    SV_vboxadd = os.system('grep "vboxadd" /etc/passwd /etc/shadow')
    SV_postgres = os.system('grep "postgres" /etc/passwd /etc/shadow')
    
    #
    # Specific STIG directed delete accounts
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
    # Specific privileged user accounts to note for possible follow-on verification.  Do not delete but note as warnings.
    #
    if SV_vagrant == 0:
        print 'Vagrant account found.\n'
        vagrant_sudo = os.system('grep sudo /etc/group | grep vagrant')
        UID = os.system("cat /etc/passwd | grep vagrant | cut -f3 -d':'")
        if vagrant_sudo == 0:
            print 'Vagrant account has sudo privileges. This is not necessarily an issue and is noted for administrator review.\n'
        if UID < 1000:
            print 'Vagrant user ID is less than 1000. This is not necessarily an issue if the account is used solely as a system account.\n'
    
    if SV_vboxadd == 0:
        print 'Vboxadd account found.\n'
        vboxadd_sudo = os.system('grep sudo /etc/group | grep vboxadd')
        UID = os.system("cat /etc/passwd | grep vboxadd | cut -f3 -d':'")
        if vboxadd_sudo == 0:
            print 'Vboxadd account has sudo privileges. This is not necessarily an issue and is just noted for administrator information.\n'
        if UID < 1000:
            print 'Vboxadd user ID is less than 1000. This is not necessarily an issue if the account is used solely as a system account.\n'
    
    if SV_postgres == 0:
        print 'Postgres account found.\n'
        postgres_sudo = os.system('grep sudo /etc/group | grep postgres')
        UID = os.system("cat /etc/passwd | grep postgres | cut -f3 -d':'")
        if postgres_sudo == 0:
            print 'Postgres account has sudo privileges. This is not necessarily an issue and is just noted for administrator information.\n'
        if UID < 1000:
            print 'Postgres user ID is less than 1000. This is not necessarily an issue if the account is used solely as a system account.\n'

def SV4339r5():
    #
    # Rule Id: SV-4339r5 - The Linux NFS Server must not have the insecure file locking option
    #
    
    nsfd_rule = os.system('pgrep -l nfsd')
    
    if nsfd_rule == 0:
        print 'NFS Server process running. This is not necessarily an issue unless users hava unrestricted privileges.\n'

def SV4342r5():
    #
    # Rule Id: SV-4342r5 - The x86 CTRL-ALT-Delete key sequence must be disabled.
    #
    # Read the /etc/init/control-alt-delete.conf file and comment out contents of file if not already done.
    #
    
    if "# exec shutdown -r now" not in open('/etc/init/control-alt-delete.conf').read():
        print 'Removing control-alt-delete capability.\n'
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

def SV28646r1():
    #
    # Rule Id: SV-28646r1 - Use approved DOD time clocks
    # Replace Ubuntu default wit DOD approved
    #
    # Read text file with approved clocks and replace Ubuntu default in /etc/ntp.conf.
    #
    
    if os.path.exists("/etc/ntp.conf"):
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
    else:
        print 'NTP server not installed or found. Please install and rerun the setup.\n'
        

def SV27109r1():
    #
    # Rule ID: SV-27109r1_rule - Remove nullok
    #
    # Remove nullok from /etc/pam.d scripts

    nullok_check = os.system('grep nullok /etc/pam.d/*')

    if nullok_check == 0:
        os.system('sed -i s/nullok//g /etc/pam.d/*')
        print 'Nullok removed from /etc/pam.d/*.\n'
    else:
        print 'Nullok not found in /etc/pam.d. No files changed.\n'

def SV4255r4():
    #
    # Rule Id: SV-4255r4 - The system boot loader must require authentication.
    # Configure grub with root only authorization
    #
    # prompt for root boot loader password and configure grub config with new, secure, password.
    #
    
    # prompt for new boot loader password
    
    if "password_pbkdf2 root" not in open('/etc/grub.d/40_custom').read():
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
    else:
        print 'Grub security already updated. No changes made.\n'

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

def SV29956r1():
    #
    # Rule Id: SV-29956r1 - The /etc/gshadow file must be group-owned by root
    # Change /etc/gshadow to root if not root.  OOB is shadow.
    #
    if os.path.exists("/etc/gshadow"):
        gsown = str.strip(os.popen('stat -c %G /etc/gshadow').read())
        if gsown != "root":
            print '/etc/gshadow file group changed to root.\n'
            os.system('chgrp root /etc/gshadow')
        else:
            print '/etc/gshadow file group is already owned by root.\n'
    else:
        print '/etc/gshadow does not exist.\n'

def SV27291r1():
    # Add the STIG audit rules
    # SV-27291r1_rule, SV-27295r1_rule, SV-27302r1_rule
    # Plus change the buffers for the busy system
    
    if "# STIG Based Audits" not in open('/etc/audit/audit.rules').read() and "-b 750" not in open('/etc/audit/audit.rules').read():
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
            print 'audit.rules configured.\n'
    else:
        print 'audit.rules already configured. Not changed.\n'

def SV26518r1(admin1):
    #
    # SV-26518r1_rule. The audit system must alert the SA when the audit storage volume approaches its capacity.
    #
    # This changes the /etc/audit/audit.conf to email the administrator when the storage volume is reached.
    # It uses the admin account name set above.  
    #
    
    if os.path.exists("/etc/audit/auditd.conf"):
        if "space_left_action = email" not in open('/etc/audit/auditd.conf').read():
                with open("/etc/audit/auditd.conf", "r+") as audit_conf_file:
                    lines = audit_conf_file.readlines()
                    audit_conf_file.seek(0)
                    for line in lines:
                        if 'space_left_action' in line:
                            audit_conf_file.write("space_left_action = email\n")
                        elif 'action_mail_acct' in line:
                            audit_conf_file.write("action_mail_acct = %s\n" %str(admin1))
                audit_conf_file.close()
                print 'auditd.conf configured.\n'
        else:
            print '/etc/audit/auditd.conf already configured. Not changed.\n'
    else:
        print '/etc/audit/audit.conf not found. Check audit package installationa\n.'

def SV26444r1():
    #
    # Rule Id: SV-26444r1 - The /etc/gshadow file must must have mode 0400
    # Change /etc/gshadow to 0400.  OOB is 0640.
    #
    
    if os.path.exists("/etc/gshadow"):
        gsmod = oct(stat.S_IMODE(os.stat('/etc/gshadow').st_mode))
        if gsmod != "0400":
            print '/etc/gshadow file mod changed to 0400.\n'
            os.system('chmod u+r,u-wxs,g-rwxs,o-rwxt /etc/gshadow')
        else:
            print '/etc/gshadow file mode is already 0400. File permissions not changed.\n'
    else:
        print '/etc/gshadow does not exist.\n'

def SV1015r7():
    #
    # Rule Id: SV-1015r7 - The ext3 filesystem type must be used for primary Linux
    # file system partitions.  Check to see if /etc/fstab lists any ext1 or ext2 for
    # listed active partitions.
    #
    # The script cannot fix the problem.  It only notes this as a CATII failure that
    # must be fixed separately.
    #
     
    if os.path.exists("/etc/fstab"):
        with open("/etc/fstab", "r") as fstab_file:
            lines = fstab_file.readlines()
            fstab_file.seek(0)
            count = 0
            for line in lines:
                pos_1 = line[0]
                if pos_1 == '#': continue
                elif 'ext1' in line:
                    print '/etc/fstab contains an active ext1 file system.  CATII failure.\n'
                elif 'ext2' in line:
                    print '/etc/fstab contains an active ext2 file system.  CATII failure.\n'
                else: continue
        fstab_file.close()
    else:
        print '/etc/fstab does not exist.\n'

def SV1055r5():
    #
    # Rule Id: SV-1055r5 - The /etc/security/access.conf file must have mode 0640 or less
    # Change from 0644 to 0640.
    #
    
    if os.path.exists("/etc/security/access.conf"):
        acmod = oct(stat.S_IMODE(os.stat('/etc/security/access.conf').st_mode))
        if acmod != "0640":
            print '/etc/security/access.conf file mod changed to 0640.\n'
            os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/security/access.conf')
        else:
            print '/etc/security/access.conf file mod is already 0640. File permissions not changed.\n'
    else:
        print '/etc/security/access.conf does not exist.\n'

def SV4336r5():
    #
    # Rule Id: SV-4336r5 - The /etc/sysctl.conf file must have mode 0600 or less
    # Change from 0644 to 0600.
    #
    
    if os.path.exists("/etc/sysctl.conf"):
        scmod = oct(stat.S_IMODE(os.stat('/etc/sysctl.conf').st_mode))
        if scmod != "0600":
            print '/etc/security/access.conf file mod changed to 0600.\n'
            os.system('chmod u+rw,u-xs,g-rwxs,o-rwxt /etc/sysctl.conf')
        else:
            print '/etc/sysctl.conf file mod is already 0600. File permissions not changed.\n'
    else:
        print '/etc/sysctl.conf does not exist.\n'

def SV12541r2():
    #
    # Rule Id: SV-12541r2 - The /etc/securetty file must have mode 0640 or less
    # Change from 0644 to 0640.
    #
    
    if os.path.exists("/etc/securetty"):
        stymod = oct(stat.S_IMODE(os.stat('/etc/securetty').st_mode))
        if stymod != "0640":
            print '/etc/securetty file mode changed to 0640.\n'
            os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/sysctl.conf')
        else:
            print '/etc/securetty file mod is already 0640. File permissions not changed.\n'
    else:
        print '/etc/securetty does not exist.\n'

def SV27059r1():
    #
    # Rule Id: SV-27059r1 - Vendor-recommended software patches and updates, and
    # system security patches and updates, must be installed and up-to-date.
    #
    
    if "Download-Upgradeable-Packages \"1\"" not in open('/etc/apt/apt.conf.d/10periodic').read():
        with open("/etc/apt/apt.conf.d/10periodic", "r+") as periodic_file:
            periodic_file.seek(0)
            periodic_file.truncate()
            periodic_file.write("APT::Periodic::Update-Package-Lists \"1\";\n")
            periodic_file.write("APT::Periodic::Download-Upgradeable-Packages \"1\";\n")
            periodic_file.write("APT::Periodic::AutocleanInterval \"7\";\n")
            periodic_file.write("APT::Periodic::Unattended-Upgrade \"1\";\n")
        periodic_file.close()
        print 'Vendor upgrades set to automatic.\n'
    else:
        print 'Vendor upgrade settings unchanged.\n'

def SV26307r1():
    #
    # Rule Id: SV-26307r1_rule
    # Rule Title: The system time synchronization method must use cryptographic algorithms to verify 
    # the authenticity and integrity of the time data.
    #
    # OOB Ubuntu does not have this configured.  This will be noted as a failure in the check log only.
    # No separate configuration check will be done.
    #

    if os.path.exists("/etc/ntp.conf"):
        time_crypto_check = os.system('grep ^server /etc/ntp.conf | grep \'( key | autokey )\'')
        if time_crypto_check != 0:
            print 'CATII SV-26307r1 Failure. NTP not configured to use cryptographic algorithms to verify the authenticity and integrity of the time data.\n'
        else:
            print 'Appears NTP servers employ time cryptographic algorithmsi to verify time data.\n'
    else:
        print 'ntp.conf file not found.  Install ntp server..\n'

def SV26297r1():
    #
    # Rule Id: SV-26297r1_rule - The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.
    #
    
    if os.path.exists("/etc/ntp.conf"):
        ntpconfmod = oct(stat.S_IMODE(os.stat('/etc/ntp.conf').st_mode))
        if ntpconfmod != "0640":
            os.system('chmod u+rw,u-xs,g+r,g-wxs,o-rwxt /etc/ntp.conf')
            print '/etc/ntp.conf file mode changed to 0640.\n'
        else:
            print '/etc/ntp.conf file mod is already 0640. File permissions not changed.\n'
    else:
        print 'SV-26297r1 CATII Failure /etc/ntp.conf does not exist.\n'

def SV42691r4():
    #
    #Rule Id: SV-4269-1r4_rule - The system must not have the unnecessary games account.
    #
    # Checks for user games and removes the user and group games if user games is
    # found.  Group is also removed by the system since it is only associated with the user
    # games and not required by the system otherwise.
    #
    # Remove directories associated with games. 

    games_user_check=os.system('grep ^games /etc/passwd')
    if games_user_check == 0:
        os.system('deluser --remove-home --remove-all-files games')
        print 'User games and group games removed from system.\n'
        if os.path.isdir('/usr/local/games'):
            os.system('rm -R /usr/local/games')
        if os.path.isdir('/usr/games'):
            os.system('rm -R /usr/games')
    else:
        print 'User games not found.\n'

def SV42692r4():
    #
    # Rule Id: SV-4269-2r4_rule - The system must not have the unnecessary news account.
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

def SV42695r4():
    #
    # Rule Id: SV-4269-5r4_rule - The system must not have the unnecessary lp account.
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

def SV27090r1():
    #
    # Rule Id: SV-27090r1_rule - The system must disable accounts after three consecutive 
    # unsuccessful login attempts.  This sets the level in the /etc/pam.d/common-auth file.
    #
    
    if "auth required pam_tally.so per_user magic_root deny=3 lock_time=4 onerr=fail" not in open('/etc/pam.d/common-auth').read():
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
        print '/etc/pam.d/common-auth modified.\n'
        com_auth_file.close()
    else:
        print '/etc/pam.d/common-auth changes already in file. No change to file made.\n'

def passwdr1():
    #
    # Addresses Rule Id's: SV-27101r1_rule and SV-27129r1_rule - Cannot change password more than once a day,
    # and must be changed every 60 days.
    #
    
    if "PASS_MAX_DAYS   60" not in open('/etc/login.defs').read():
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
        print 'Password time rules modified.\n'
    else:
        print 'Password time rules already set. Not modified.\n'

def passwdr2():
    #
    # Rule Id: SV-27114r1_rule, SV-26321r1_rule, SV-27122r1_rule, SV-27125r1_rule, SV-27128r1_rule, SV-26323r1_rule,
    # SV-26344r1_rule, Must have four character changes between old and new password, 
    # at least one lowercase alphabetic character, at least one numeric character, at least one special character, 
    # no more than three consecutive repeating characters and at least four characters changed between the old and new password.
    #
    
    if "pam_cracklib.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 difok=4" not in open('/etc/login.defs').read() and "pam_unix.so obscure remember=5 use_authtok try_first_pass sha512" not in open('/etc/login.defs').read():
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
        print 'Password complexity rules modified.\n'
    else:
        print 'Password complexity rules already set. Not modified.\n'

def SV27146r1():
    #
    # Rule Id: SV-27146r1_rule.  The system must prevent the root account from directly logging in except from the system console.  
    # This removes console login from /etc/securetty.
    #
    
    if os.path.exists("/etc/securetty"):
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
        print '/etc/securetty root login modified.\n'

def SV1047r7():
    #
    # Rule Id: SV-1047r7_rule. The system must not permit root logins using remote access programs such as ssh.
    #
    
    if os.path.exists("/etc/ssh/sshd_config"):
        if "PermitRootLogin no" not in open('/etc/ssh/sshd_config').read():
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
            print 'root remote login disabled.\n'
        else:
            print 'root remote login already disabled.\n'
    else:
        print '/etc/ssh/sshd_config file not found.\n'

def SV787r9():
    #
    # Rule Id: SV-787r9_rule. System log files must have mode 0640 or less permissive.
    # Changes /var/log mod from 0755 to 0640
    # Changed to 0645 because Postgres needs execute on its log file.  Really, fails otherwise.
   
    if os.path.exists("/var/log"):
        logmod = oct(stat.S_IMODE(os.stat('/var/log').st_mode))
        if logmod != "0645":
            os.system('chmod u+rw,u-xs,g+r,g-wx,o+rx,o-wt /var/log')
            print '/var/log file mode changed to 0645.\n'
        else:
            print '/var/log mode is already 0645.\n'
    else:
        print '/var/log does not exist.\n'

def SV800r7():
    #
    # Rule Id: SV-800r7_rule. The /etc/shadow (or equivalent) file must have mode 0400
    # Changes file permissions to 0400
    #
    
    if os.path.exists("/etc/shadow"):
        logmod = oct(stat.S_IMODE(os.stat('/etc/shadow').st_mode))
        if logmod != "0400":
            os.system('chmod chmod 0400 /etc/shadow')
            print '/etc/shadow file mode changed to 0400.\n'
        else:
            print '/etc/shadow mode is already 0400.\n'
    else:
        print '/etc/shadow does not exist.\n'

def SV12482r4():
    #
    # SV-12482r4_rule. All global initialization files must have mode 0644 or less permissive.
    #
    
    if os.path.exists("/etc/profile.d/rvm.sh"):
        os.system('chmod 0644 /etc/profile.d/rvm.sh')
        print '/etc/profile.d/rvm.sh mode changed.\n'
    if os.path.exists("/etc/security"):
        os.system('chmod 0644 /etc/security')
        print '/etc/security mode changed.\n'
    if os.path.exists("/etc/security/limits.d"):
        os.system('chmod 0644 /etc/security/limits.d')
        print '/etc/security/limits.d mode changed.\n'
    if os.path.exists("/etc/security/namespace.d"):
        os.system('chmod 0644 /etc/security/namespace.d')
        print '/etc/security/namespace.d mode changed.\n'
    if os.path.exists("/etc/security/namespace.init"):
        os.system('chmod 0644 /etc/security/namespace.init')
        print '/etc/security/namespace.init mode changed.\n'

def SV808r6():
    #
    # Addresses Rule Id's: SV-808r6_rule - All local initialization files must have mode 0740 or less permissive.
    #
    
    if "UMASK           077" not in open('/etc/login.defs').read():
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
        print 'UMASK set to 077.\n'
    else:
        print 'UMASK at 077 - unchanged.\n'

    os.system('find /home/vagrant -maxdepth 1 -name \'.*\' -type f -exec chmod 740 {} +')

def SV905r6():
    #
    # Addresses Rule Id's: SV-905r6_rule - All local initialization files must have mode 0740 or less permissive.
    #

    print 'Checking and changing user local initialization files.\n'

    os.system('find $(awk -F: \'{ print $6 }\' /etc/passwd|sort|uniq|grep -v \'^/$\') -maxdepth 1 -type f \( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bashrc -o -name .bash_logout -o -name .bash_profile -o -name .bash_login -o -name .env -o -name .dispatch -o -name .emacs -o -name .exrc \) -perm /7037 -exec chmod u-s,g-wxs,o-rwxt {} \;')

    os.system('find $(awk -F: \'{ print $6 }\' /etc/passwd|sort|uniq|grep -v \'^/$\') -maxdepth 1 \( -name .dt -o -name .dtprofile \) -perm /7022 -exec chmod u-s,g-ws,o-wt {} \;')

def SV924r6():
    #
    # Addresses Rule Id's: SV-924r6_rule - Device files and directories must only be writable by users with a system account or as
    # configured by the vendor.  See notes for the devices not changed.
    #
    
    if os.path.exists("/dev/ptmx"):
        os.system('chmod 0644 /dev/ptmx')
        print '/dev/ptmx mode changed.\n'
    else:
        print '/dev/ptmx mode unchanged.\n'

    if os.path.exists("/dev/urandom"):
        os.system('chmod 0644 /dev/urandom')
        print '/dev/urandom mode changed.\n'
    else:
        print '/dev/urandom mode unchanged.\n'

    if os.path.exists("/dev/tty"):
        os.system('chmod 0644 /dev/tty')
        print '/dev/tty mode changed.\n'
    else:
        print '/dev/tty mode unchanged.\n'

    if os.path.exists("/dev/random"):
        os.system('chmod 0644 /dev/random')
        print '/dev/random mode changed.\n'
    else:
        print '/dev/random mode unchanged.\n'

    if os.path.exists("/dev/full"):
        os.system('chmod 0644 /dev/full')
        print '/dev/full mode changed.\n'
    else:
        print '/dev/full mode unchanged.\n'

    # Add weekly cron jobs to check if there are unauthorized setuid files or unauthorized modification to
    # authorized setuid files
    if not os.path.exists("/etc/cron.weekly/sgid-files-check"):
        os.system('cp ./doc/sgid-files-check /etc/cron.weekly;chmod 700 /etc/cron.weekly/sgid-files-check;chown root:root /etc/cron.weekly/sgid-files-check;')
        print 'sgid-files-check cron job created.\n'
    else:
        print 'sgid-files-check found. Not changed.\n'

    if not os.path.exists("/etc/cron.weekly/suid-files-check"):
        os.system('cp ./doc/suid-files-check /etc/cron.weekly;chmod 700 /etc/cron.weekly/suid-files-check;chown root:root /etc/cron.weekly/suid-files-check;')
        print 'suid-files-check cron job created.\n'
    else:
        print 'suid-files-check found. Not changed.\n'

def SV27341r1():
    #
    # SV-27341r1_rule and SV-27344r1_rule - Cron file permission mode <= 0700, cron directory <= 755.
    #
    
    os.system('find /etc/cron* -type f | xargs chmod 700')
    os.system('find /var/spool/cron* -type f | xargs chmod 700')
    os.system('find /etc/cron* -type d | xargs chmod 755')
    os.system('find /var/spool/cron* -type d | xargs chmod 755')
    print 'Cron file permissions set.\n'

def SV27320r1():
    #
    # SV-27320r1_rule - Access to the cron utility must be controlled using the cron.allow and/or cron.deny file(s).
    #
    # This script creates a cron.allow and adds root as the only user.
    #
    # Do this after the above changes of cron.allow will change from the STIG modei setting for the file.
    
    if not os.path.exists("/etc/cron.allow"):
        os.system('touch /etc/cron.allow')
    else:
        print '/etc/cron.allow found. Not modified.\n'
    if "root" not in open('/etc/cron.allow').read():
        print '/etc/cron.allow set to root.\n'
    else:
        print '/etc/cron.allow is already set to root. Not changed\n'
    os.system('chmod 0600 /etc/cron.allow')
    os.system('chown root:root /etc/cron.allow')
    print '/etc/cron.allow permissions set.\n'

def SV27352r1():
    #
    # SV-27352r1_rule - Cron logging must be implemented.
    #
    # SV-27357r1_rule - The cronlog file must exist and have mode 0600 or less permissive.
    #
    
    if not os.path.exists("/var/log/cron.log"):
        os.system('touch /var/log/cron.log')
        print 'Cron logfile created.\n'
    else:
        os.system('find /var/log/cron.log -perm /7177 -exec chmod u-xs,g-rwxs,o-rwxt {} \;')
        print 'Cron logfile already exists. Permissions set.\n'

    if "cron.*                          /var/log/cron.log" not in open('/etc/rsyslog.d/50-default.conf').read():
        with open("/etc/rsyslog.d/50-default.conf", "r+") as cron_log_file:
            lines = cron_log_file.readlines()
            cron_log_file.seek(0)
            cron_log_file.truncate()
            for line in lines:
                if "#" in line and "/var/log/cron.log" in line:
                    cron_log_file.write('cron.*                          /var/log/cron.log\n')
                else:
                    cron_log_file.write(line)
        print 'cron logging implemented.\n'
        cron_log_file.close()
    else:
        print 'Cron logging already implemented.\n'

def SV27379r1():
    #
    # SV-27379r1_rule - Access to the "at" utility must be controlled via the at.allow and/or at.deny file(s).
    #
    # This script creates a at.allow and adds root as the only user.
    #
    
    if not os.path.exists("/etc/at.allow"):
        os.system('touch /etc/at.allow')
        os.system('echo "root" > /etc/at.allow')
        os.system('chmod 0600 /etc/cron.allow')
        os.system('chown root:root /etc/at.allow')
        print '/etc/at.allow created, root user added, permissions set to 0600 and ownership set to root.\n'
    elif "root" not in open('/etc/at.allow').read():
        os.system('echo "root" > /etc/at.allow')
        os.system('chmod 0600 /etc/cron.allow')
        os.system('chown root:root /etc/at.allow')
        print '/etc/at.allow root user added to file, permissions set to 0600 and ownership set to root.\n'
    else:
        os.system('chmod 0600 /etc/cron.allow')
        os.system('chown root:root /etc/at.allow')
        print '/etc/at.allow files already exist.  Permissions set to 0600 and ownership set to root.\n'

def SV4364r7():
    #
    # SV-4364r7_rule - The "at" directory must have mode 0755 or less permissive.
    # SV-4365r7_rule - The "at" directory must be owned by root, bin, or sys.
    #
    
    if os.path.exists("/var/spool/cron/atjobs"):
        os.system('chmod 0700 /var/spool/cron/atjobs')
        os.system('chown root:root /var/spool/cron/atjobs')
        print '/var/spool/cron/atjobs permissions set to 0700 and ownership set to root.\n'
    else:
        print '/var/spool/cron/atjobs doesn\'t exist.\n'

def SV26572r1():
    #
    # SV-26572r1_rule - The at.deny file must be group-owned by root, bin, sys, or cron.
    #
    
    if os.path.exists("/var/spool/cron/atdeny"):
        os.system('chown root:root /etc/at.deny')
        print '/etc/at.deny ownership changed to root.\n'
    else:
        print '/var/spool/cron/atdeny doesn\'t exist.\n'

def SV29290r1():
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
    
    if not os.path.exists("/etc/sysctl.conf"):
        if "# Disable STIG IP source routing" not in open('/etc/sysctl.conf').read():
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
            print 'STIG IP source routing directed disabling added.\n'
        else:
            print 'STIG IP source routing directed in effect.\n'
    else:
        print '/etc/sysctl.conf doesn\'t exist.\n'
    
    if not os.path.exists("/etc/modprobe.d/blacklist.conf"):
        if "iblacklist ipv6" not in open('/etc/modprobe.d/blacklist.conf').read():
            os.system('echo "# STIG SV-26919r1_rule" >> /etc/modprobe.d/blacklist.conf')
            os.system('echo "blacklist ipv6" >> /etc/modprobe.d/blacklist.conf')
            print 'ipv6 added to the blacklist in /etc/modprobe.d/blacklist.conf.\n'
        else:
            print 'ipv6 already blacklisted /etc/modprobe.d/blacklist.conf.\n'
    else:
        print '/etc/modprobe.d/blacklist.conf doesn\'t exist.\n'

def SV12507r6():
    #
    # SV-12507r6_rule - The SMTP service HELP command must not be enabled
    #
    # This will zero out the help file thus providing no information.
    #
    
    if not os.path.exists("/etc/mail/helpfile"):
        with open("/etc/mail/helpfile", "r+") as mailhelp_file:
            lines = mailhelp_file.readlines()
            mailhelp_file.seek(0)
            mailhelp_file.truncate()
            mailhelp_file.write("\n")
            mailhelp_file.close()
            print 'SMTP service HELP command disabled.\n'
    else:
        print '/etc/mail/helpfile doesn\'t exist.\n'

def SV28408r1():
    #
    # SV-28408r1_rule - The ftpusers file must contain account names not allowed to use FTP.
    # SV-28405r1_rule - The ftpusers file must exist
    # This will zero out the help file thus providing no information.
    #
    
    if not os.path.exists("/etc/ftpusers"):
        os.system('touch /etc/ftpusers')
        os.system('chmod 0640 /etc/ftpusers')
        os.system('echo "#" > /etc/ftpusers')
        print '/etc/ftpusers file created and user and permissions set.\n'
    else:
        os.system('chmod 0640 /etc/ftpusers')
        os.system('echo "#" > /etc/ftpusers')
        print '/etc/ftpusers file user and permissions set.\n'

def SV26740r1():
    #
    # SV-26740r1_rule - The /etc/syslog.conf (rsyslog.conf for Ubuntu) file must have mode 0640 or less permissive.
    #
    
    if os.path.exists("/etc/rsyslog.conf"):
        os.system('chmod 0640 /etc/rsyslog.conf')
        print '/etc/rsyslog.conf mode set.\n'

def SV26749r1():
    #
    # SV-26749r1_rule - The SSH client must be configured to only use the SSHv2 protocol.
    # SV-28763r1_rule - The SSH client must use a FIPS 140-2 validated cryptographic module.
    # SV-26754r1_rule - The SSH client must be configured to only use FIPS 140-2 approved ciphers.
    # SV-26755r1_rule - The SSH client must be configured to not use CBC-based ciphers.
    # SV-26756r1_rule - The SSH client must be configured to only use MACs that employ FIPS 140-2 approved cryptographic hash algorithms.
    #

    if "#   MACs" in open('/etc/ssh/ssh_config').read() and "#   Tunnel" not in open('/etc/ssh/ssh_config').read():
        with open("/etc/ssh/ssh_config", "r+") as ssh_config_file:
            lines = ssh_config_file.readlines()
            ssh_config_file.seek(0)
            ssh_config_file.truncate()
            for line in lines:
                if "#   Protocol 2,1" in line:
                    ssh_config_file.write("Protocol 2\n")
                elif "#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc" in line:
                    ssh_config_file.write(line)
                    ssh_config_file.write("Ciphers aes128-ctr,aes192-ctr,aes256-ctr\n")
                elif "#   MACs" in line:
                    ssh_config_file.write("MACs hmac-sha1\n")
                elif "#   Tunnel no" in line:
                    ssh_config_file.write("Tunnel no\n")
                else:
                    ssh_config_file.write(line)
        ssh_config_file.close()
        print '/etc/ssh/ssh_config configured for protocols and cyphers.\n'
    else:
        print '/etc/ssh/ssh_config already configured for proper protocols and cyphers.\n'

def SV28762r1():
    #
    # SV-28762r1_rule - The SSH daemon must use a FIPS 140-2 validated cryptographic module.
    # SV-26753r1_rule - The SSH daemon must be configured to only use MACs that employ FIPS 140-2 approved cryptographic hash algorithms.
    # SV-26752r1_rule - The SSH daemon must be configured to not use CBC ciphers.
    # SV-26751r1_rule - The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.
    #
    
    if "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" not in open('/etc/ssh/sshd_config').read() and "MACs hmac-sha1" not in open('/etc/ssh/sshd_config').read():
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
        print '/etc/ssh/sshd_config configured for protocols and cyphers.\n'
    else:
        print '/etc/ssh/sshd_config already configured for proper protocols and cyphers.\n'

def SV29414r1():
    #
    # SV-29414r1_rule
    #
    # uncomment if going to implement the ldd restriction.
    
    if os.path.exists("/usr/bin/ldd"):
        os.system('chmod a-x /usr/bin/ldd')
        print 'Execute permissions removed for all users on /usr/bin/ldd.\n'

def SV26192r():
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

def iptablerules():
    #
    # add iptable rules
    # SV-26973r1_rule - The system must employ a local firewall
    # SV-26975r1_rule - The system's local firewall must implement a deny-all, allow-by-exception policy.
    # SV-26192r1_rule - The Lightweight User Datagram Protocol (UDP-Lite) must be disabled unless required.
    #
    # Script added to root home directory
    
    if not os.path.exists("/root/iptables.sh"):
        os.system('cp ./doc/iptables.sh /root;chmod 700 /root/iptables.sh')
        print 'iptables rules file added to root directory.\n'
    else:
        os.system('chmod 700 /root/iptables.sh')
        print 'iptables rules exist in root directory. File permission settings verified.\n'
        
    if not os.path.exists("/root/save-then-clear-iptables.sh"):
        os.system('cp ./doc/save-then-clear-iptables.sh /root;chmod 700 /root/save-then-clear-iptables.sh')
        print 'iptables rules save script added to root directory.\n'
    else:
        os.system('chmod 700 /root/save-then-clear-iptables.sh')
        print 'iptables rules save script exists in root directory. File permission settings verified.\n'

def grubmod():
    #
    # SV-4250r5_rule - The system's boot loader configuration file(s) must have mode 0600 or less permissive.
    #
    # File is 0444.  Setting to 0400.
    #

    if os.path.exists("/boot/grub/grub.cfg"):
        btmod = oct(stat.S_IMODE(os.stat('/boot/grub/grub.cfg').st_mode))
        if btmod != "0400":
            os.system('chmod 0400 /boot/grub/grub.cfg')
            print '/boot/grub/grub.cfg mode changed to 0400.\n'
        else:
            print '/boot/grub/grub.cfg mode is already 0400. File permissions not changed.\n'
    else:
        print '/boot/grub/grub.cfg file not found.\n' 

def acl_check():
    #
    #
    #
    #

    if os.path.exists("/etc/gshadow"):
        ACLOUT="+"
        ACLOUT=os.system('getfacl --skip-base /etc/gshadow 2>/dev/null')
        if ACLOUT != ""
            os.system('setfacl --remove-all /etc/gshadow')
            print '/etc/gshadow extended ACL removed.\n'
        else
            print '/etc/gshadow does not have an extended ACL.\n'

    if os.path.exists("/etc/security/access.conf"):
        ACLOUT="+"
        ACLOUT=os.system('getfacl --skip-base /etc/security/access.conf 2>/dev/null')
        if ACLOUT != ""
            os.system('setfacl --remove-all /etc/security/access.conf')
            print '/etc/security/access.conf extended ACL removed.\n'
        else
            print '/etc/security/access.conf does not have an extended ACL.\n'

    if os.path.exists("/etc/sysctl.conf'):
        ACLOUT="+"
        ACLOUT=os.system('getfacl --skip-base /etc/sysctl.conf 2>/dev/null')
        if ACLOUT != ""
            os.system('setfacl --remove-all /etc/sysctl.conf')
            print '/etc/sysctl.conf extended ACL removed.\n'
        else
            print '/etc/sysctl.conf does not have an extended ACL.\n'

    if os.path.exists("/etc/ntp.conf'):
        ACLOUT="+"
        ACLOUT=os.system('getfacl --skip-base /etc/ntp.conf 2>/dev/null')
        if ACLOUT != ""
            os.system('setfacl --remove-all /etc/ntp.conf')
            print '/etc/ntp.conf extended ACL removed.\n'
        else
            print '/etc/ntp.conf does not have an extended ACL.\n'

    if os.path.exists("/root'):
        ACLOUT="+"
        ACLOUT=os.system('getfacl --skip-base /root 2>/dev/null')
        if ACLOUT != ""
            os.system('setfacl --remove-all /root')
            print '/root extended ACL removed.\n'
        else
            print '/root does not have an extended ACL.\n'

    if os.path.exists("/usr/sbin'):
        os.system('setfacl --remove-all /usr/sbin/*')


    if os.path.exists("/etc"):
        basepath='/etc'
        for fname in os.listdir(basepath):
            path = os.path.join(basepath, fname)
            if os.path.isdir(path):continue
            else
                var1='getfacl --skip-base' + path + '2>/dev/null' 
                ACLOUT=os.system(var)
                if ACLOUT != ""
                    var1='setfacl --remove-all' + path
                    print '/etc/gshadow extended ACL removed.\n'
                else
                    print '/etc/gshadow does not have an extended ACL.\n'
