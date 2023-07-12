#!/usr/bin/python3

import sys
import subprocess
from subprocess import Popen, PIPE
from sys import argv
#from nmap_modules import filter_ftp_output

class NmapArguments():

    # basic scan
    PORTS = argv[2]
    HOSTS = argv[3]
    BLACKLIST = ' --excludefile=/home/betaperson/scripts/scans/blacklist.txt'
    BASIC_INFORMATIONS = f'nmap -Pn -n --open -p {PORTS} -iR {HOSTS} -oA nmap'
    DEBUG = ' -dd -v '
    SPOOF = ' --spoof-mac -D RND,RND,RND,ME,RND '
    TIME_PERFORMANCE = ' -T5 --host-timeout=30 --max-retries=1 '

    # version detection scan
    VERSION_DETECTION = ' -sV --version-light '

    # NSE scans
    NSE_SCAN = ' -sC --script=ftp-anon'
    FTP_ANON = 'ftp-anon'

# define basic scan
def basic_scan():
    global nmap_basic_scan
    nmap_basic_scan = subprocess.Popen(NmapArguments().BASIC_INFORMATIONS + NmapArguments().SPOOF + NmapArguments().TIME_PERFORMANCE + NmapArguments().DEBUG + NmapArguments().VERSION_DETECTION + NmapArguments().BLACKLIST, shell=True,  universal_newlines=True).wait()

# define basic scan for output filter
def basic_scan_to_pipe():
    global nmap_basic_scan
    nmap_basic_scan = subprocess.Popen(NmapArguments().BASIC_INFORMATIONS + NmapArguments().SPOOF + NmapArguments().TIME_PERFORMANCE + NmapArguments().BLACKLIST + NmapArguments().NSE_SCAN, stdout=subprocess.PIPE, shell=True,  universal_newlines=True)

# define version detection scan
def version_detection_scan():
    global version_detection
    version_detection = Popen(NmapArguments().BASIC_INFORMATIONS + NmapArguments().SPOOF + NmapArguments().VERSION_DETECTION + NmapArguments().TIME_PERFORMANCE + NmapArguments().BLACKLIST + NmapArguments().NSE_SCAN, shell=True, universal_newlines=True).wait()

# define service filters   
def filter_ftp_output():   
    # filter output
    lines = []
    for line in nmap_basic_scan.stdout:
        lines.append(line.strip('\n'))
        if 'report' in line:
            #out = sys.stdout.write(line[20:])
            
            with open('file.txt', 'w') as file:
                file.write(str(lines))

        #elif 'open' in line:
            #sys.stdout.write(line)
        elif 'allowed' in line:
            #sys.stdout.write(lines[2])
            #sys.stdout.write(line)
            print('\033[1;93m' + line + '\033[0m')
            #sys.stdout.write(line)
        elif 'Info' in line:
            print('\033[1;93m' + line + '\033[0m')
            #sys.stdout.write(line)                
        elif '|' in line:
            print('\033[1;92m' + line + '\033[0m')
            #sys.stdout.write(line)                
        else: 
            pass

# main
if len(argv) == 4:
    if argv[1] == '1':
        #NmapArguments.NSE_SCAN+NmapArguments.FTP_ANON
        #print(NmapArguments.NSE_SCAN)
        basic_scan_to_pipe()
        filter_ftp_output()
    elif argv[1] == '2':
        if argv[2] == '21':
            NmapArguments.NSE_SCAN + 'ftp-anon'
            basic_scan_to_pipe()
            filter_ftp_output()
        else:
            service_detection_scan()
    else:
        usage()
else:
    usage()

def usage():
    print('''
learn_classes.py SCAN_TYPE PORTS HOSTS 

SCAN_TYPES = (1) Basic port scan (2) Service version detection scan
PORTS = ex.: 80,8080
HOSTS = 500 ( How many hosts to scan )''')


