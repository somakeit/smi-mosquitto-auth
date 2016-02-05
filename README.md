SMI Auth Plugin
===============
This is an authentication plugin for mosquitto that uses the So Make It members area username & password as well as a bcrypt encrypted password_file.

Building
--------
Dependencies:
 - Put the mosquitto source directory next to this one.
 - git submodile init && git submodule update #to get bcrypt library, check for security patches upstream before building.
 - Have libcurl.

Then:
<pre>make</pre>

Configuring
-----------
Put these values in the mosquitto configuration file:
<pre>
# So Make It auth plugin
auth_plugin /path/to/smi_mosquitto_auth.so

# Optional URL to SMI authentication server
auth_opt_smi_auth_url https://example.com/auth_url

# Optional password file to override SMI auths.
# Format as per password_file but passwords are hashed with bcrypt.
auth_opt_password_file /etc/mosquitto/password_file

# Optional acl file to control access to topics
# Format for each line must be:
#   user access topic
# Where: user   = POSIX regex for username
#        access = one of no,ro,wo,rw
#        topic  = POSIC regex for topic
# The file should contain no extra whitespace.
# The file is parsed from the top until a matching rule us found.
# If no match is foud access is disallowed.
# Eg:
# ^alice$ rw private.*
# ^bob$ rw private.*
# .* no private.*
# .* rw .*
auth_opt_acl_file /etc/mosquitto/acl_file
</pre>

Copying
-------
Copyright 2016 So Make It Ltd.
Licensed as GPL2.
