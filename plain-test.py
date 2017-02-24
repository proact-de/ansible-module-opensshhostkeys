#!/usr/bin/python

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
privkey = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pubkey = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

privfile = open('privkey', 'w')
privfile.write(privkey)
privfile.close()

pubfile = open('pubkey', 'w')
pubfile.write(pubkey)
pubfile.close()

