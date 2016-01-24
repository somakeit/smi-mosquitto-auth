SMI Auth Plugin
===============
This is an authentication plugin for mosquitto that uses the So Make It members area username & password as well as a bcrypt encrypted password_file.

Building
--------
Dependencies:
 - Put the mosquitto source directory next to this one.
 - git submodile init && git submodule update #to get bcrypt library, check for security patches upstream before building.
 - Have libcurl.
 - 
Then:
<pre>make</pre>

Configuring
-----------
Put these values in the mosquitto configuration file:
<pre>#So Make It auth plugin
auth_plugin /path/to/smi_mosquitto_auth.so
#Optional URL to SMI authentication server
auth_opt_smi_auth_url https://members.somakeit.org.uk/me
#Optional password file to override SMI auths, format as per password_file
#but passwords are encrypted with bcrypt.
auth_opt_password_file /etc/mosquitto/password_file</pre>
