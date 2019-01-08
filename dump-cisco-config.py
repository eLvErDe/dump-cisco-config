#!/usr/bin/python3


# pylint: disable=line-too-long


"""
Run non interactive script to dump configuration from a network equipement
"""


import argparse
import os
import pexpect
import pexpect.fdpexpect
import serial



class PexpectNetwork:
    """
    Run non interactive script to dump configuration from a network equipement
    """


    allowed_protocols = ['ssh', 'serial:9600']
    allowed_actions = ['dump', 'load']


    def __init__(
            self,
            address,
            protocol,
            username,
            password,
            action,
            filename,
            silent=False,
            enable_password=None,
    ):

        assert isinstance(address, str) and address, 'address must be a non empty string'
        assert isinstance(protocol, str) and protocol, 'protocol must be a non empty string'
        assert protocol in self.allowed_protocols, 'protocol must be one of %s' % ','.join(self.allowed_protocols)
        assert isinstance(username, str), 'username must be a string (maybe empty)'
        assert isinstance(password, str), 'password must be a string (maybe empty)'
        assert isinstance(action, str) and action, 'action must be a non empty string'
        assert action in self.allowed_actions, 'action must be one of %s' % ','.join(self.allowed_actions)
        assert isinstance(silent, bool), 'silent must be a boolean'
        assert isinstance(filename, str) and filename, 'filename must be a non empty string'
        if enable_password is not None:
            assert isinstance(enable_password, str) and enable_password, 'enable_password must be a string (maybe empty)'

        self.address = address
        self.protocol = protocol
        self.username = username
        self.password = password
        self.action = action
        self.filename = filename
        self.silent = silent
        self.enable_password = enable_password if enable_password is not None else password
        self.script = None


    @classmethod
    def command_line_args(cls):
        """ Create a command line arguments to run this as a cli script """

        parser = argparse.ArgumentParser(description='Run non interactive script to dump configuration from a network equipement', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser.add_argument('address',  type=str, help='Address of the target equipement', metavar='192.168.0.1')  # pylint: disable=bad-whitespace
        parser.add_argument('protocol', type=str, help='Protocol to use for connectiong', choices=cls.allowed_protocols)
        parser.add_argument('username', type=str, help='Username', metavar='root')
        parser.add_argument('password', type=str, help='Root', metavar='password')
        parser.add_argument('action',   type=str, help='Dump or load', choices=cls.allowed_actions)  # pylint: disable=bad-whitespace

        parser.add_argument('--filename',   type=str, help='filename to use as input or output', metavar='/tmp/config.txt', required=True)  # pylint: disable=bad-whitespace
        parser.add_argument('--silent', action='store_true', help='Do not echo-output')
        parser.add_argument('--enable-password',  type=str, help='Enable password (fallback to password if unset', metavar='enable_password', required=False)  # pylint: disable=bad-whitespace

        parsed = parser.parse_args()
        return parsed


    @property
    def command(self):
        """ Return shell command to be run """

        if self.protocol == 'ssh':
            command = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s' % (self.username, self.address)
            return command
        elif self.protocol == 'serial:9600':
            serial_obj = serial.Serial(self.address, self.protocol.split(':')[1])
            return serial_obj
        else:
            raise NotImplementedError('Protocol %s is not yet implemented')


    def _pexpect_line_answer(self, question, answer=None, timeout=2, after_as_dump_config=False):
        """ Expect a pattern an provide answer (also display output) """

        if after_as_dump_config:
            self.handle_dump_config(self.script.after.decode('utf-8'))
        else:
            if self.script.after is not None and not self.silent:
                print(self.script.after.decode('utf-8'))
        self.script.expect(question, timeout=timeout)
        if answer is not None:
            self.script.sendline(answer)
        if self.script.before is not None and not self.silent:
            print(self.script.before.decode('utf-8'))

    def run(self):
        """ Run expect against TF configure script an provide answers """

        command = self.command
        if isinstance(command, serial.serialposix.Serial):
            self.script = pexpect.fdpexpect.fdspawn(command)
            self.script.send("\03")
        else:
            self.script = pexpect.spawn(self.command)

        # Authentication
        self._pexpect_line_answer(r'(?i)^.*to the list of known hosts\.\s*(username:?|([0-9a-z-_]+@[0-9a-z-_\.]+\'s )?password:?|[0-9a-z-_]+(>|#))\s*$', timeout=5)
        if b'>' in self.script.after.lower() or b'#' in self.script.after.lower():

            if b'>' in self.script.after.lower():
                self.script.sendline('enable')
                self._pexpect_line_answer(r'(?i)^\s*enable\s*$', timeout=5)
                self._pexpect_line_answer(r'(?i)^\s*(password:?|[0-9a-z-_]+#)\s*$', timeout=5)

                if b'password' in self.script.after.lower():
                    self.script.sendline(self.enable_password)
                    # ASA output ***** when typing password
                    self._pexpect_line_answer(r'(?i)^\s*(\*+\s+)?[0-9a-z-_]+#\s*$', timeout=5)

        else:

            if b'username' in self.script.after.lower():
                self.script.sendline(self.username)
                self._pexpect_line_answer(r'(?i)^\s*password:?\s*$', timeout=5)
                self.script.sendline(self.password)
            elif b'password' in self.script.after.lower():
                self.script.sendline(self.password)

            self._pexpect_line_answer(r'(?i)\s*[0-9a-z-_]+(>|#)\s*$', timeout=5)

            if b'>' in self.script.after.lower():
                self.script.sendline('enable')
                self._pexpect_line_answer(r'(?i)^\s*enable\s*$', timeout=5)
                self._pexpect_line_answer(r'(?i)^\s*(password:?|[0-9a-z-_]+#)\s*$', timeout=5)

                if b'password' in self.script.after.lower():
                    self.script.sendline(self.enable_password)
                    # ASA output ***** when typing password
                    self._pexpect_line_answer(r'(?i)^\s*(\*+\s+)?[0-9a-z-_]+#\s*$', timeout=5)

        # Disable pagination
        self.script.sendline('terminal length 0')
        self._pexpect_line_answer(r'(?i)^\s*terminal length 0\s*$', timeout=5)
        self._pexpect_line_answer(r'(?i)^\s*([0-9a-z-_]+#|.*ERROR: % Invalid input detected at.*)\s*$', timeout=5)

        # ASA wants terminal pager 0 instead
        if b'invalid input detected at' in self.script.after.lower():
            self.script.sendline('terminal pager 0')
            self._pexpect_line_answer(r'(?i)^\s*terminal pager 0\s*$', timeout=5)
            self._pexpect_line_answer(r'(?i)^\s*[0-9a-z-_]+#\s*$', timeout=5)

        if self.action == 'dump':

            # Show running config
            self.script.sendline('show running-config')

            # Running config is here
            self._pexpect_line_answer(r'(?i)^\s*.*[0-9a-z-_]+#\s*$', timeout=5)


        elif self.action == 'load':

            self.script.sendline('configure terminal')
            self._pexpect_line_answer(r'(?i)^\s*configure terminal\s*$', timeout=5)

            self._pexpect_line_answer(r'(?i)^\s*.*[0-9a-z-_]\(config\)#\s*$', timeout=5)
            with open(self.filename, 'r', encoding='utf-8') as load_fh:
                for line in load_fh.readlines():
                    self.script.sendline(line)

            self._pexpect_line_answer(r'(?i)^\s*.*[0-9a-z-_]+#\s*$', timeout=5)

        else:
            raise NotImplementedError('Unknown action')

        # Disconnect
        self.script.sendline('exit')
        try:
            self._pexpect_line_answer(pexpect.EOF, None, after_as_dump_config=True)
        except pexpect.exceptions.TIMEOUT:
            if not self.protocol.startswith('serial:'):
                raise


    def handle_dump_config(self, message):
        """ Argument message contain buffer with all configuration """


        with open(self.filename, 'w', encoding='utf-8') as dump_fh:
            dump_fh.write(message)
        os.chmod(self.filename, 0o640)

if __name__ == '__main__':


    CONFIG = PexpectNetwork.command_line_args()

    EXPECT = PexpectNetwork(**vars(CONFIG))

    EXPECT.run()
