stig based system security lockdown
====

JAM
LMN Solutions
Version 0.2
Dec 2013
 
The main scripts in this project are based on the DISA unclassified STIG
documentation.  They automate securing a system OS or database based on a 
review of the STIG documentation and guidelines.

The scripts are designed for the ROGUE JCTD and decisions are based on that project
but are compatible with any compatible system since the decisions made for the lockdowns are
intended to secure a system with intent for authority to connect and operate on
secure networks.

The OS script is designed and tested for Ubuntu 12.03 and 12.04 LTS.

The database script is designed for Postgresql witg PostGIS

The scripts assume an "out of the box" Ubuntu or Postgresql installation.  Any system 
unique considerations will be annotated in the lockdown scripts.

The scripts only correct findings not found to be compliant with the DISA STIG or guides.
A manual review was conducted of all CATI and CATII.  CATIII items are not corrected. In 
some cases findings were considered "site specific issues" and are not addressed in the 
scripts, nor are findings deemed out of scope. An example of this is Postgres not using a 
FIPS compliant algorythm to secure passwords. The project these scripts are designed for
will not address those issues.

This is a work in progress with an intent of having a gamma release for testing in the spring 
of 2013.
