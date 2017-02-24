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
            - Size (in bits) of the hostkey key to generate
    type:
        required: false
        default: "RSA"
        choices: [ RSA, DSA ]
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
except ImportError:
    python_cryptography_found = False
else:
    python_cryptography_found = True  

import os

class PrivateKeyError(Exception):
    pass

class PrivateKey(object):

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
        elif self.type == "RSA1":
            self.name = "ssh_host_key"
        else:
            raise PrivateKeyError("Unknown key type.")

        self.fullpath = "%s/%s" % (self.path, self.name)


    def generate(self, module):
        """ Generate a hostkey pair """

        # if privkey is already there check size
        if os.path.exists(self.fullpath):
            try:
                with open(self.fullpath, "rb") as key_file:
                    self.privkey = crypto_serialization.load_pem_private_key(key_file.read(), password=None, backend_default=default_backend())
            except IOError:
                raise PrivateKeyError(get_exception())

            # If size is wrong, delete the key. A new key will be generated in the next step.
            if self.privkey.key_size != self.size:
                self.remove()
            else:
                self.changed = False

        # If there is no key or user has set "force"
        elif not os.path.exists(self.fullpath) or self.force:
            if self.type == "RSA":
                self.key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=self.size, backend=crypto_default_backend())
            elif self.type == "DSA":
                self.key = crypto_dsa.generate_private_key(keysize=self.size, backend=crypto_default_backend())
            else:
                raise PrivateKeyError("Unknown key type.") # can't happen - already caught in __init__
 
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
                raise PrivateKeyError(get_exception())
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
                raise PrivateKeyError(e)
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
            state = dict(default='present', choices=['present', 'absent'], type='str'),
            size  = dict(default=4096,                                     type='int'),
            type  = dict(default='RSA',     choices=['RSA', 'DSA'],        type='str'),
            force = dict(default=False,                                    type='bool'),
            path  = dict(default='/etc/ssh',                               type='path'),
        ),
        supports_check_mode  = True,
        add_file_common_args = True,
    )

    if not python_cryptography_found:
        module.fail_json(msg='the python pyOpenSSL module is required')

    path = module.params['path']
    base_dir = module.params['path']

    if not os.path.isdir(base_dir):
        module.fail_json(name=base_dir, msg='The directory %s does not exist or the file is not a directory' % base_dir)

    if not module.params['mode']:
        module.params['mode'] = int('0600', 8)

    private_key = PrivateKey(module)
    if private_key.state == 'present':

        if module.check_mode:
            result = private_key.dump()
            result['changed'] = module.params['force'] or not os.path.exists(path)
            module.exit_json(**result)

        try:
            private_key.generate(module)
        except PrivateKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))
    else:

        if module.check_mode:
            result = private_key.dump()
            result['changed'] = os.path.exists(path)
            module.exit_json(**result)

        try:
            private_key.remove()
        except PrivateKeyError:
            e = get_exception()
            module.fail_json(msg=str(e))

    result = private_key.dump()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
