stig based system security lockdown
====

JAM
LMN Solutions
Version 0.9
Mar 2014

The scripts in this project are designed to secure PostGIS 9.1 and Ubuntu 12.04.  The scripts are based 
on the DISA unclassified STIG documentation for securing Redhat and Oracle, as well as general DISA guidelines 
for applications, databases and operating systems.  They automate securing a system OS or database based on a 
review of the STIG documentation and guidelines.

The OS lockdown is designed and tested for Ubuntu 12.03 and 12.04 LTS.
The database lockdowns are TBD.

The scripts are designed for the ROGUE JCTD project and decisions are based on that project.
The lockdown is designed with a complete ROGUE system build in mind, not after the OS installation.  
This means some of the database lockdowns will be added to this script.  Even so, the scripts are 
compatible or configurable with other Ubuntu 12.03 or 12.04 since the final build will perform checks 
for ROGUE build decisions that may not be part of an OS specific installation.

A Postgresql database script will eventually be written.  PostGIS is the database of choice for the project
and is part of the Geoserver distribution primarily for admin purposes but ROGUE is using this distribution
database for an open distribution, single server distribution architecture.

There are implementation specific considerations that are identified in the lockdown report. Adding the 
report with this distribution has not been decided yet.

The scripts only correct findings not found to be compliant with the DISA STIG or guides.
A manual review was conducted of all CATI and CATII.  CATIII items are not corrected. 

Any issue found to already be in effect through the manual review is not checked by the scripts. In
some cases findings were considered "site specific issues" and are not addressed in the
scripts, nor are findings deemed out of scope. An example of this is Postgres not using a
FIPS compliant algorithm to secure passwords. The project these scripts are designed for
will not address those issues.

This is a work in progress with an intent of having a gamma release for testing in the spring of 2014.

To Do:

There are several CATS that need more research or made more flexible.  Time was important to get a 90% solution
so some of the lockdows were moved to do later. 

A complete "To Do" list will be compiled later but for now this is what I am working on:

Completed - Break all the rule lockdowns into separate functions and add a function call list to the top.  This way the executed functions can be adjusted to testing / trouble shooting.

Still to do (some of them anyway):

- SV-26307r1. Do a check for ntp crypto servers and not a default unclass assumption response.
- SV-27203r1_rule. Move the postgres user home out of the postgres application directory.
- SV-760r6_rule. Remove postgres direct login since it is an application account.  Not sure what to do with the vagrant account yet.
- SV-905r6_rule. Make this a rule for all accounts and not just a hack for the vagrant account.
- Build more flexibility into some of the checks instead of the abrupt abort you get.  Time was of the essence but a graceful exit from the function is better.
