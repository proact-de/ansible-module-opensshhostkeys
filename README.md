# OpenSSH Hostkey Module for Ansible

This Module allows you to manipulate OpenSSH Hostkeys from an Ansible Playbook.

## Installation

Drop this directory into your Ansible modules folder. Destination hosts will need python cryptography installed to be able to use this module. You will have to ensure this manually with your playbook.

### Example usage

```yml
- name: Harden SSHd | remove RSA1 hostkey.
  openssh_hostkey:
    type: RSA1
    state: absent
    path: "{{ pacopenssh_conf_dir }}"
  notify: [ 'restart_sshd' ]

- name: Harden SSHd | remove DSA hostkey.
  openssh_hostkey:
    type: DSA
    state: absent
    path: "{{ pacopenssh_conf_dir }}"
  notify: [ 'restart_sshd' ]

- name: Harden SSHd | Enforce 4096 bits RSA hostkey.
  openssh_hostkey:
    type: RSA
    size: 4096
    state: present
    path: "{{ pacopenssh_conf_dir }}"
  notify: [ 'restart_sshd' ]

- name: Harden SSHd | Enforce 521 bits ECDSA key.
  openssh_hostkey:
    type: ECDSA
    state: absent
    path: "{{ pacopenssh_conf_dir }}"
  notify: [ 'restart_sshd' ]

- name: Harden SSHd | Enforce existence of ED25519 hostkey.
  openssh_hostkey:
    type: ED25519
    size: 128
    state: present
    path: "{{ pacopenssh_conf_dir }}"
  notify: [ 'restart_sshd' ]
```

## License

Copyright 2017-2019 Proact Deutschland GmbH
Authors: Patrick Dreker <patrick.dreker@proact.de>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the

GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

