# coding: utf-8
from __future__ import print_function
import os
import re
import sys
import socket
from telnetlib import Telnet
from subprocess import Popen, PIPE

if sys.version_info.major == 2:
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser


def getoutput(cmd):
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    out, _ = p.communicate()
    return out.strip(), p.wait()


def test_connect(ip, port, timeout=5):
    tn = Telnet()
    try:
        tn.open(ip, port, timeout=timeout)
        return True
    except (socket.timeout, socket.error, socket.gaierror):
        print('\nCannot connect IP:%s port:%s\n' % (ip, port))
        return False


class AUTOSSH(object):
    EXPECT_SSH = """set timeout 10
spawn ssh -o "StrictHostKeyChecking no" -p{port} -l {username} {ip}
expect {{
    "assword:" {{
        send "{password}\r";
        exp_continue
    }}
    "denied" {{
        puts "Wrong password"
        exit 1;
    }}
    "ogin:" {{
        interact
    }}
}}
"""
    EXPECT_SCP = """set timeout 10
spawn scp -P{port} {src_file} {username}@{ip}:{dest_file}
expect {{
    "assword:" {{
        send "{password}\r"
    }}
    "defied" {{
        puts "Wrong password"
        exit 1;
    }}
}}
expect eof

"""

    def __init__(self):
        self.config_file = self._config_file()
        self.config = self.get_config()

    def get_config(self):
        config = ConfigParser()
        config.read(self.config_file)
        return config

    def run(self, hostname=None, ip=None, username=None, password=None, port=22):
        if hostname != None and self.has_hostname_cache(hostname):
            login_info = self.query_from_hostname(hostname)
            cmd = self.EXPECT_SSH.format(**login_info)
            os.system("expect -c '{}'".format(cmd))
        elif ip != None and self.has_ip_cache(ip):
            login_info = self.query_from_ip(ip)
            cmd = self.EXPECT_SSH.format(**login_info)
            os.system("expect -c '{}'".format(cmd))
        elif username and password:
            can_connect = test_connect(ip, int(port))
            if not can_connect:
                sys.exit(1)

            print(hostname, ip, username, password, port)
            cmd = self.EXPECT_SSH.format(ip=ip,
                                         username=username,
                                         password=password,
                                         port=port)
            retcode = os.system("expect -c '{}'".format(cmd))
            if retcode == 0:
                self.record_login_info(hostname, ip, username, password, port)
            else:
                print('\nPlease confirm login username or password\n')
                sys.exit(1)
        else:
            print('\nThe %s has no cache and Cannot find Login'
                  'info in the input message\n' % ip)
            sys.exit(1)

    def has_ip_cache(self, ip):
        return self.config.has_section(ip)

    def has_hostname_cache(self, hostname):
        return self.config.has_section(hostname)

    def query_from_ip(self, ip):
        return {'ip': ip,
                'username': self.config.get(ip, 'username'),
                'password': self.config.get(ip, 'password'),
                'port': self.config.get(ip, 'port')
                }

    def query_from_hostname(self, hostname):
        return {'ip': self.config.get(hostname, 'ip'),
                'username': self.config.get(hostname, 'username'),
                'password': self.config.get(hostname, 'password'),
                'port': self.config.get(hostname, 'port')
                }

    def record_login_info(self, hostname, ip, username, password, port):
        self.config.add_section(ip)
        self.config.set(ip, 'username', username)
        self.config.set(ip, 'password', password)
        self.config.set(ip, 'port', port)

        with open(self.config_file, 'w') as f:
            self.config.write(f)
        if(hostname!=None):
            self.config.add_section(hostname)
            self.config.set(hostname, 'ip', ip)
            self.config.set(hostname, 'username', username)
            self.config.set(hostname, 'username', username)
            self.config.set(hostname, 'password', password)
            self.config.set(hostname, 'port', port)

            with open(self.config_file, 'w') as f:
                self.config.write(f)

    @staticmethod
    def _config_file():
        autossh_home = os.getenv('AUTOSSH_ROOT')
        if not autossh_home:
            raise OSError('Cannot load AUTOSSH_ROOT environ variable')
        config_file = os.path.join(autossh_home, 'config.ini')
        return config_file


if __name__ == '__main__':
    argv_len = len(sys.argv)
    if argv_len < 2:
        print('\nPlease input something\n')
        sys.exit(1)
    temp = sys.argv[1]
    arr = temp.split(":")

    if len(arr) == 1:
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', arr[0]):
            hostname = None
            ip = temp
        else:
            hostname = temp
            ip = None
    elif len(arr) == 2:
        hostname = arr[0]
        ip = arr[1]

    if argv_len > 4:
        username = sys.argv[2]
        password = sys.argv[3]
        port = sys.argv[4]
    elif argv_len > 3:
        username = sys.argv[2]
        password = sys.argv[3]
        port = '22'
    else:
        username = None
        password = None
        port = '22'
    autossh = AUTOSSH()
    autossh.run(hostname, ip, username, password, port)
