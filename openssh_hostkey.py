#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Patrick Dreker <patrick.dreker@teamix.de>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'teamix',
                    'version': '0.1'}


DOCUMENTATION = '''
---
module: SSHd_Hostkeys
author: "Patrick Dreker"
version_added: "2.3"
short_description: Manages OpenSSH hostkeys.
description:
    - "This module manages OpenSSH hostkeys. Keys can be queried, checked and generated. Currently limited to RSA and DSA."
requirements:
    - "python-cryptography"
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the host key should exist or not, taking action if the state is different from what is stated.
    size:
        required: false
        default: 4096
        description:
            - Size (in bits) of the hostkey key to generate.
    type:
        required: false
        default: "RSA"
        choices: [ RSA, DSA, ECDSA ]
        description:
            - The algorithm used to generate the hostkey
    force:
        required: false
        default: False
        choices: [ True, False ]
        description:
            - Should the key be regenerated even it it already exists
    path:
        required: false
        default: /etc/ssh
        description:
            - Name of the directory in which the generated hostkey will be written. Filename will depend on the keytype.
'''

EXAMPLES = '''
# Generate an OpenSSh hostkey with the default values (4096 bits, RSA)
- openssh_hostkey:
    path: /etc/ssl/private/ansible.com.pem
# Generate an OpenSSL private key with a different size (2048 bits)
- openssh_hostkey:
    size: 2048
# Force regenerate an OpenSSH hostkey if it already exists
- openssh_hostkey:
    force: True
# Generate an OpenSSL private key with a different algorithm (DSA)
- openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    type: DSA
'''

RETURN = '''
size:
    description: Size (in bits) of the TLS/SSL private key
    returned:
        - changed
        - success
    type: integer
    sample: 4096
type:
    description: Algorithm used to generate the TLS/SSL private key
    returned:
        - changed
        - success
    type: string
    sample: RSA
filename:
    description: Path to the generated TLS/SSL private key file
    returned:
        - changed
        - success
    type: string
    sample: /etc/ssl/private/ansible.com.pem
'''

from ansible.module_utils.basic import *

try:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.backends import default_backend as crypto_default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    from cryptography.hazmat.primitives.asymmetric import dsa as crypto_dsa
    from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec

except ImportError:
    python_cryptography_found = False
else:
    python_cryptography_found = True  

import os

class HostkeyError(Exception):
    pass

class Hostkey(object):

    def __init__(self, module):
        self.size = module.params['size']
        self.state = module.params['state']
        self.type = module.params['type']
        self.force = module.params['force']
        self.path = module.params['path']
        self.mode = module.params['mode']
        self.changed = True
        self.check_mode = module.check_mode
        if self.type == "RSA":
            self.name = "ssh_host_rsa_key"
        elif self.type == "DSA":
            self.name = "ssh_host_dsa_key"
        elif self.type == "ECDSA":
            self.name = "ssh_host_ecdsa_key"
        elif self.type =="ED25519":
            self.name = "ssh_host_ed25519_key"
            self.size = 3000 # somewhat arbitrary, equivalent RSA Key Size

        self.fullpath = "%s/%s" % (self.path, self.name)

    def check_key(self):
        """ Check params of existing key """
        if self.type == "RSA" and self.size < 1024:
                raise HostkeyError("RSA keys must at least be 1024 bits.")
        elif self.type == "DSA" and self.size != 1024:
                raise HostkeyError("DSA keys can only be 1024 bits.")
        elif self.type == "ECDSA" and self.size not in [256, 384, 521]: # yes, that is *really* 521 bits, not a typo!
                raise HostkeyError("ECDSA key must be either 256, 384 or 521 bits (yes, 521 not 512!)")
        elif self.type =="ED25519" and self.size != 3000:
                raise HostkeyError("ED25519 keys have a fixed size, which cannot be altered.") # can't really happen, size is ignored for ED25519
        
        # if privkey is already there check size
        self.key_exists = False
        self.key_current_size = 0
        if os.path.exists(self.fullpath):
            if self.type == "ED25519":
                self.curve = "EC25519"
                self.key_current_size = 3000 # somewhat erbitrary, equivalent RSA Key Size
                self.key_exists = True
            else:
                try:
                    with open(self.fullpath, "rb") as key_file:
                        self.privkey = crypto_serialization.load_pem_private_key(key_file.read(), password=None, backend=crypto_default_backend())
                except IOError:
                    raise HostkeyError(get_exception())

                self.key_exists = True
                if self.type != "ECDSA":
                    self.key_current_size = self.privkey.key_size
                else:
                    self.pubkey = self.privkey.public_key()
                    if self.pubkey.curve.name == "secp256r1":
                        self.key_current_size = 256
                    elif self.pubkey.curve.name == "secp384r1":
                        self.key_current_size = 384
                    elif self.pubkey.curve.name == "secp521r1":
                        self.key_current_size = 521
                    else:
                        self.curve = self.pubkey.curve.name

    def generate(self, module):
        """ Generate a hostkey pair """

        # If size is wrong, delete the key. A new key will be generated in the next step.
        if self.key_current_size != self.size:
            self.remove()
        else:
            self.changed = False

        # If there is no key or user has set "force"
        if not self.key_exists or self.force:
            if self.type == "RSA":
                self.key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=self.size, backend=crypto_default_backend())
            elif self.type == "DSA":
                self.key = crypto_dsa.generate_private_key(keysize=self.size, backend=crypto_default_backend())
            elif self.type == "ECDSA":
                if self.size == 256:
                    self.curve = crypto_ec.SECP256R1()
                elif self.size == 384:
                    self.curve = crypto_ec.SECP384R1()
                elif self.size == 521:
                    self.curve = crypto_ec.SECP521R1()
                self.key = crypto_ec.generate_private_key(curve=self.curve, backend=crypto_default_backend())
            elif self.type == "ED25519":
                self.size = 3000
                self.curve = "EC25519"
            else:
                raise HostkeyError("Unknown key type.")
            
            if self.type != "ED25519":
                self.privkey = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                self.pubkey = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

                try:
                    privfile = os.open(self.fullpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, self.mode)
                    os.write(privfile, privkey)
                    os.close(privfile)
                    pubfile = os.open(self.fullpath + ".pub", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, self.mode)
                    os.write(pubfile, pubkey)
                    os.close(pubfile)
                except IOError:
                    self.remove()
                    raise HostkeyError(get_exception())
            else:
                # use ssh-keygen to generate ED25519 Hostkeys
                # Keyfile must not exist, as there is no "foce-overwrite" in ssh-keygen
                retcode = subprocess.call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "''", "-f", "ed25519_test"])
        else:
            self.changed = False

        file_args = module.load_file_common_arguments(module.params)
        if module.set_fs_attributes_if_different(file_args, False):
            self.changed = True


    def remove(self):
        """Remove the hostkey from the filesystem."""

        try:
            os.remove(self.fullpath)
            os.remove(self.fullpath + ".pub")
        except OSError:
            e = get_exception()
            if e.errno != errno.ENOENT:
                raise HostkeyError(e)
            else:
                self.changed = False

    def dump(self):
        """Serialize the object into a dictionnary."""

        result = {
            'size': self.size,
            'type': self.type,
            'filename': self.path,
            'changed': self.changed,
        }

        return result

## FIXME: This needs reworking!
def main():

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(default='present', choices=['present', 'absent'],   type='str'),
            size  = dict(default=4096,                                       type='int'),
            type  = dict(default='RSA',     choices=['RSA', 'DSA', 'ECDSA'], type='str'),
            force = dict(default=False,                                      type='bool'),
            path  = dict(default='/etc/ssh',                                 type='path'),
        ),
        supports_check_mode  = True,
        add_file_common_args = True,
    )

    if not python_cryptography_found:
        module.fail_json(msg='the python python-cryptography module is required')

    path = module.params['path']

    if not os.path.isdir(path):
        module.fail_json(name=base_dir, msg='The directory %s does not exist or the file is not a directory' % base_dir)

    if not module.params['mode']:
        module.params['mode'] = int('0600', 8)

    hostkey = Hostkey(module)
    try:
        hostkey.check_key()
    except HostkeyError as e:
        module.fail_json(msg=str(e))
    
    if hostkey.state == 'present':

        if module.check_mode:
            result = hostkey.dump()
            result['no_key'] = not hostkey.key_exists
            result['key_wrong_size'] = (hostkey.key_exists and hostkey.key_current_size != hostkey.size)
            result['key_current_size'] = hostkey.key_current_size
            try:
                result['ecc_curve'] = hostkey.ecc_curve
            except AttributeError:
                pass

            result['changed'] = module.params['force'] or not hostkey.key_exists or (hostkey.key_exists and hostkey.key_current_size != hostkey.size)
            module.exit_json(**result)

        try:
            hostkey.generate(module)
        except HostkeyError:
            e = get_exception()
            module.fail_json(msg=str(e))
    else:

        if module.check_mode:
            result = hostkey.dump()
            result['changed'] = self.key_exists
            module.exit_json(**result)

        try:
            hostkey.remove()
        except HostkeyError:
            e = get_exception()
            module.fail_json(msg=str(e))

    result = hostkey.dump()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
