#########################################################################################################################
# STIG OS lockdown script for Ubuntu 12.04. This script sets the environment and calls the functions script.
# This script allows for individual lockdowns be called as needed.
#
# JAM
# LMN Solutions
# Version 0.99
# 29 April 2014
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
import stig_functions

#########################################################################################################################
#
# Get the system administrator user name for use in some of the scripts
#
#########################################################################################################################

print 'Get system administrator account name to configure administrator functions identified by the STIG.\n'

admin1=1
admin2=2

while admin1 != admin2:
    admin1 = raw_input("Enter system administrator account name:")
    admin2 = raw_input("Reenter system administrator account name:")
    if admin1 != admin2:
        print "Entered system administrator account name does not match."

# Function List

# Install and configure packages
stig_functions.audit()
stig_functions.ntp_server()
stig_functions.tripwire(admin1)
stig_functions.mail()
stig_functions.snort(admin1)
stig_functions.clamav(admin1)
stig_functions.rkhunter(admin1)
stig_functions.chkrootkit(admin1)
stig_functions.debsums()

# Purge Packages
stig_functions.rpcbind()
stig_functions.tpcdump()
stig_functions.popularity()

# CATI Policies
stig_functions.SV4268r5()
stig_functions.SV4339r5()
stig_functions.SV4342r5()
stig_functions.SV28646r1() # ./doc/ntp-servers.txt contains a list of default servers.  Update for approved organization servers as appropriate.
stig_functions.SV27109r1()
stig_functions.SV4255r4()

# CATII Policies
stig_functions.SV29956r1()
stig_functions.SV27291r1()
stig_functions.SV26518r1(admin1)
stig_functions.SV26444r1()
stig_functions.SV1015r7()
stig_functions.SV1055r5()
stig_functions.SV4336r5()
stig_functions.SV12541r2()
#stig_functions.SV27059r1() - disabled because automatic updates break the system.  Use CM to manage.
stig_functions.SV26307r1()
stig_functions.SV26297r1()
stig_functions.SV42691r4()
stig_functions.SV42692r4()
stig_functions.SV42695r4()
stig_functions.SV27090r1()
stig_functions.passwdr1()
stig_functions.passwdr2()
stig_functions.SV27146r1()
stig_functions.SV1047r7()
stig_functions.SV787r9()
stig_functions.SV12482r4()
stig_functions.SV808r6()
stig_functions.SV905r6()
stig_functions.SV924r6()
stig_functions.SV27320r1()
stig_functions.SV27341r1()
stig_functions.SV27352r1()
stig_functions.SV27379r1()
stig_functions.SV4364r7()
stig_functions.SV26572r1()
stig_functions.SV29290r1()
stig_functions.SV12507r6()
stig_functions.SV26740r1()
stig_functions.SV26749r1()
stig_functions.SV28762r1()
stig_functions.SV28408r1()
#stig_functions.SV29414r1() - ldd chmod.  Disabled because you get some weird issues when it's changed.  Need to investigate more.
stig_functions.SV26192r()
stig_functions.iptablerules()
stig_functions.grubmod()

print 'End of STIG OS lockdown script.\n'
