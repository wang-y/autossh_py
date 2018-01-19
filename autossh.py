# coding: utf-8
from __future__ import print_function
import os
import re
import sys
import socket
import base64
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
                'password': base64.decodestring(self.ip_config.get(ip, 'password')),
                'port': self.ip_config.get(ip, 'port')
                }

    def query_from_hostname(self, host):
        return {'ip': self.hostname_config.get(host, 'ip'),
                'username': self.hostname_config.get(host, 'username'),
                'password': base64.decodestring(self.hostname_config.get(host, 'password')),
                'port': self.hostname_config.get(host, 'port')
                }

    def record_login_info(self, host, ip, username, password, port):
        self.ip_config.add_section(ip)
        self.ip_config.set(ip, 'username', username)
        self.ip_config.set(ip, 'password', base64.encodestring(password))
        self.ip_config.set(ip, 'port', port)
        with open(self.ip_config_file, 'w') as f:
            self.ip_config.write(f)
        if host is not None:
            self.hostname_config.add_section(host)
            self.hostname_config.set(host, 'ip', ip)
            self.hostname_config.set(host, 'username', username)
            self.hostname_config.set(host, 'password', base64.encodestring(password))
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
    def print_ip_list():
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
        sys.exit(1)

    @staticmethod
    def print_hostname_list():
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
        sys.exit(1)

    @staticmethod
    def remove_config(arrays):
        autossh_home = os.getenv('AUTOSSH_ROOT')

        ipconfig = ConfigParser()
        ip_config_file = os.path.join(autossh_home, 'ip_config.ini')
        ipconfig.read(ip_config_file)

        hostconfig = ConfigParser()
        hostname_config_file = os.path.join(autossh_home, 'hostname_config.ini')
        hostconfig.read(hostname_config_file)

        for str in arrays:
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str):
                ipconfig.remove_section(str)
                with open(ip_config_file, 'w') as f:
                    ipconfig.write(f)
                secs=hostconfig.sections()
                for h in secs:
                    if hostconfig.get(h,'ip') == str:
                        hostconfig.remove_section(h)
                        with open(hostname_config_file, 'w') as f:
                            hostconfig.write(f)
                        break
                    else:
                        continue
            else:
                _ip=hostconfig.get(str,'ip')
                ipconfig.remove_section(_ip)
                with open(ip_config_file, 'w') as f:
                    ipconfig.write(f)
                hostconfig.remove_section(str)
                with open(hostname_config_file, 'w') as f:
                    hostconfig.write(f)
        sys.exit(1)


if __name__ == '__main__':
    argv_len = len(sys.argv)
    if argv_len < 2:
        print("""
        # 输入 --ips 或者 -i 查询IP列表
        # 输入 --hosts 或者 -h 查询HOST列表
        
        # 第一次连接
        autossh [HOSTNAME:]IP USERNAME PASSWORD [PORT]
        
        # HOSTNAME 可选参数
        # PORT 可选参数，默认 22
        
        # 再次连接
        autossh IP
        
        # 如果有HOSTNAME,再次连接
        autossh HOSTNAME
        
        # 如果之前连接没有添加HOSTNAME，那么可以
        autossh HOSTNAME:IP
        
        #删除host或ip
        autossh --remove hostname/ip 或者 autossh -r hostname/ip
        """)
        sys.exit(1)
    temp = sys.argv[1]
    autossh = AUTOSSH()
    if temp == "--ips" or temp == "-i":
        autossh.print_ip_list()
    elif temp == "--hosts" or temp == "-h":
        autossh.print_hostname_list()
    elif temp == "--remove" or temp == "-r":
        if argv_len < 3:
            print("请输入 想要移除的hostname或者ip!")
            sys.exit(1)
        else :
            arrays=sys.argv
            del arrays[0]
            del arrays[0]
            autossh.remove_config(arrays)
            sys.exit(1)
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
