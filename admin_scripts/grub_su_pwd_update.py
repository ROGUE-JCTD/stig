#########################################################################################################################
# Grub loader superuser password change and configuration
# 
# JAM
# LMN Solutions
# Version 0.1
# Dec 2013
#########################################################################################################################
# 
# This script is designed as an administrator script to change the Grub loader
# superuser password, configure the Grub 40 custom script and update grub to
# enforce grub superuser access security.

# Load the imports required by the script.
import os
import subprocess
import stat
import pexpect
import getpass

# prompt for new boot loader password

#set password capture variables
pwd1=1
pwd2=2

while pwd1 != pwd2:
    pwd1 = getpass.getpass("Enter new Grub Loader Superuser Password:")
    pwd2 = getpass.getpass("Reenter new Grub Loader Superuser Password:")
    if pwd1 != pwd2:
        print "Passwords do not match."

# Feed password to the grub password script
child = pexpect.spawn('grub-mkpasswd-pbkdf2')
child.expect ('Enter password:')
child.sendline (pwd1)
child.expect ('Reenter password:')
child.sendline (pwd1)
child.expect ('is ')
grub_pwd = child.readline()
grub_pwd = grub_pwd.strip()

# configure grub_40 file with new superuser password information
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
    print 'Grub security update failed. Fix errors and rerun or configure manually.\n'

