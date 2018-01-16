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
        self.ip_config_file = self._ip_config_file()
        self.hostname_config_file = self._hostname_config_file()
        self.ip_config = self.get_ip_config()
        self.hostname_config = self.get_hostname_config()

    def get_ip_config(self):
        config = ConfigParser()
        config.read(self.ip_config_file)
        return config

    def get_hostname_config(self):
        config = ConfigParser()
        config.read(self.hostname_config_file)
        return config

    def run(self, host=None, ip=None, username=None, password=None, port=22):
        if hostname is not None and self.has_hostname_cache(host):
            login_info = self.query_from_hostname(host)
            cmd = self.EXPECT_SSH.format(**login_info)
            os.system("expect -c '{}'".format(cmd))
        elif ip is not None and self.has_ip_cache(ip):
            login_info = self.query_from_ip(ip)
            if host is not None:
                self.hostname_config.add_section(host)
                self.hostname_config.set(host, 'ip', ip)
                self.hostname_config.set(host, 'username', self.ip_config.get(ip, 'username'))
                self.hostname_config.set(host, 'password', self.ip_config.get(ip, 'password'))
                self.hostname_config.set(host, 'port', self.ip_config.get(ip, 'port'))
                with open(self.hostname_config_file, 'w') as f:
                    self.hostname_config.write(f)
            cmd = self.EXPECT_SSH.format(**login_info)
            os.system("expect -c '{}'".format(cmd))
        elif username and password:
            can_connect = test_connect(ip, int(port))
            if not can_connect:
                sys.exit(1)
            cmd = self.EXPECT_SSH.format(ip=ip,
                                         username=username,
                                         password=password,
                                         port=port)
            retcode = os.system("expect -c '{}'".format(cmd))
            if retcode == 0:
                self.record_login_info(host, ip, username, password, port)
            else:
                print('\nPlease confirm login username or password\n')
                sys.exit(1)
        else:
            print('\nThe %s has no cache and Cannot find Login'
                  'info in the input message\n' % ip)
            sys.exit(1)

    def has_ip_cache(self, ip):
        return self.ip_config.has_section(ip)

    def has_hostname_cache(self, host):
        return self.hostname_config.has_section(host)

    def query_from_ip(self, ip):
        return {'ip': ip,
                'username': self.ip_config.get(ip, 'username'),
                'password': self.ip_config.get(ip, 'password'),
                'port': self.ip_config.get(ip, 'port')
                }

    def query_from_hostname(self, host):
        return {'ip': self.hostname_config.get(host, 'ip'),
                'username': self.hostname_config.get(host, 'username'),
                'password': self.hostname_config.get(host, 'password'),
                'port': self.hostname_config.get(host, 'port')
                }

    def record_login_info(self, host, ip, username, password, port):
        self.ip_config.add_section(ip)
        self.ip_config.set(ip, 'username', username)
        self.ip_config.set(ip, 'password', password)
        self.ip_config.set(ip, 'port', port)
        with open(self.ip_config_file, 'w') as f:
            self.ip_config.write(f)
        if host is not None:
            self.hostname_config.add_section(host)
            self.hostname_config.set(host, 'ip', ip)
            self.hostname_config.set(host, 'username', username)
            self.hostname_config.set(host, 'password', password)
            self.hostname_config.set(host, 'port', port)
            with open(self.hostname_config_file, 'w') as f:
                self.hostname_config.write(f)

    @staticmethod
    def _ip_config_file():
        autossh_home = os.getenv('AUTOSSH_ROOT')
        if not autossh_home:
            raise OSError('Cannot load AUTOSSH_ROOT environ variable')
        ip_config_file = os.path.join(autossh_home, 'ip_config.ini')
        return ip_config_file

    @staticmethod
    def _hostname_config_file():
        autossh_home = os.getenv('AUTOSSH_ROOT')
        if not autossh_home:
            raise OSError('Cannot load AUTOSSH_ROOT environ variable')
        hostname_config_file = os.path.join(autossh_home, 'hostname_config.ini')
        return hostname_config_file

    @staticmethod
    def _print_ip_list():
        config = ConfigParser()
        autossh_home = os.getenv('AUTOSSH_ROOT')
        if not autossh_home:
            raise OSError('Cannot load AUTOSSH_ROOT environ variable')
        ip_config_file = os.path.join(autossh_home, 'ip_config.ini')
        config.read(ip_config_file)
        secs=config.sections()
        print ('IP LIST:\n')
        for ip in secs:
            print(ip+'\t@'+config.get(ip,'username'))

    @staticmethod
    def _print_hostname_list():
        config = ConfigParser()
        autossh_home = os.getenv('AUTOSSH_ROOT')
        if not autossh_home:
            raise OSError('Cannot load AUTOSSH_ROOT environ variable')
        hostname_config_file = os.path.join(autossh_home, 'hostname_config.ini')
        config.read(hostname_config_file)
        secs = config.sections()
        print('HOST LIST:\n')
        for host in secs:
            print(host+':'+config.get(host,'username')+'@'+config.get(host,'ip')+'\n')


if __name__ == '__main__':
    argv_len = len(sys.argv)
    if argv_len < 2:
        print("""
        输入 --ips 或者 -i 查询IP列表\n
        输入 --hosts 或者 -h 查询IP列表\n
        输入 [hostname:]ip username password port 连接服务器并储存\n
        """)
        sys.exit(1)
    temp = sys.argv[1]
    autossh = AUTOSSH()
    if temp == "--ips" or temp == "-i":
        autossh._print_ip_list()
    elif temp == "--hosts" or temp == "-h":
        autossh._print_hostname_list()
    else:
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
        autossh.run(hostname, ip, username, password, port)
