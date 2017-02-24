#!/usr/bin/python

import subprocess

retcode = subprocess.call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "''", "-f", "ed25519_test"])
print "Command returned retcode: %i" % retcode 