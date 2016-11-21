#!/usr/bin/env python

from executor import execute
from executor.ssh.client import RemoteCommand
import time
import sys


# host settings
HOSTS = { 

    'node1.example.com': { 
        'user': 'me',
        'port': 22,
        'id_file': '/home/me/.ssh/id_rsa'
    },
    'node2.example.com': {
        'user': 'me',
        'port': 22,
        'id_file': '/home/me/.ssh/id_rsa'
    }
    
}

# script settings
REMOTE_DIR = '/tmp/'
LOCAL_DIR = '/tmp/'
FNAME = "${HOSTNAME}_$(date +%Y-%m-%d_%T).pcap"
TCPDUMP_CMD = 'tcpdump -s0 -pni any port 1812 or port 1813' # Script does -w, -W and -C 
FETCH_CAPTURES = True


# 'advanced' script settings

FULL_FNAME = '{0}{1}'.format(REMOTE_DIR, FNAME)
CHECK_S = "TCPDUMP STARTED"
TCPDUMP_CMD_FULL = "echo -e \"{fname}\";{capcmd} -C 500 -G -W 1 -w {fname}& echo \"{check} \n$!\"".format(fname=FULL_FNAME, capcmd=TCPDUMP_CMD, check=CHECK_S)
EXIT_ON_ERR = True
REMOTE_SILENT = True

def quit(rcode = 1):
    exit(rcode)

def log_info(msg, remove_newline=False):
    inf_msg = ' ::INFO::   {0}'.format(msg)
    if not remove_newline:
        print(inf_msg)
    else:
        print(inf_msg, end="")

def log_debug(msg):
    dbg_msg = ' ::DEBUG::  {0}'.format(msg)
    print(dbg_msg)

def log_err(msg):
    err_msg = ' ::ERROR::  {0}'.format(msg)
    print(err_msg)

    if EXIT_ON_ERR:
        quit(1)

def log_warning(msg):
    warn_msg = ' ::WARNING:: {0}'.format(msg)
    print(warn_msg)


def send_r_cmd(host, settings, r_cmd):
        rport = settings['port']
        id_file = settings['id_file']
        ruser = settings['user']
        cmd = RemoteCommand(host, r_cmd, capture=True, ssh_user=ruser, port=rport, batch_mode=False, identity_file=id_file, async=True, silent=REMOTE_SILENT)
        cmd.start()
        return cmd

def fetch_files(rhost, settings, cap_result):
        rport = settings['port']
        ruser = settings['user']
        rid_file = settings['id_file']
        file_loc = cap_result['file_location']
        fetch_cmd = 'scp -i {id_file} -P {port} {user}@{host}:{file} {locdir}'.format(user=ruser, id_file=rid_file, port=rport, host=rhost, file=file_loc, locdir=LOCAL_DIR )
        execute(fetch_cmd)

print('=== HAZARDCAP VERSION 0.1 ===')

cap_result = {}
cmd_res = {}
host_len = len(HOSTS)
log_info('Waiting for node(s) to start capture')

for host in HOSTS:
    try:
        cap_result[host] = {}
        log_debug('Connecting to {0}'.format(host))
        cmd_res[host] = send_r_cmd(host, HOSTS[host], TCPDUMP_CMD_FULL)

    except RemoteCommandFailed as e:
        log_err(e)


all_started = False
start_count = 0

while not all_started:
    for host in HOSTS:
        if not CHECK_S in cmd_res[host].output:
            time.sleep(1)
        else:
            start_count += 1
            output = cmd_res[host].output.splitlines()
            cap_result[host]['pid'] = int(output[-1])
            cap_result[host]['file_location'] = output[0]
            cmd_res[host].terminate()
            log_debug('Capture started on {0}'.format(host))
            if start_count >= host_len:
                all_started = True
                log_info('Capture started on {0} node(s)'.format(host_len))
                start_ts = int(time.time())


stop_capture = False
while not stop_capture:
    try:
        log_info('Enter \'d\' to show duration, \'x\' to stop capture: ', True)
        cmd_input = input()
        if cmd_input is 'd':
            duration = int(time.time()) - start_ts
            log_info('Capture running for {0} seconds'.format(str(duration)) )
        elif cmd_input is 'x':
            stop_capture = True
        else:
            continue

    except KeyboardInterrupt as e:
        stop_capture = True


# This does not seem to work...
'''for host in HOSTS:
    if cmd_res[host].is_running:
        cmd_res[host].terminate()
        log_debug('Terminated capture on {0}'.format(host))
    else:
        log_warning('Capture on node {0} was not running when we tried to terminate it'.format(host))
'''

# .. so start new SSH connection and send terminate signal
for host in HOSTS:
    cap_pid = cap_result[host]['pid']
    kill_cmd = 'kill {pid}; echo "$?"'.format(pid=cap_pid)
    cmd_res[host] = send_r_cmd(host, HOSTS[host], kill_cmd)
    log_debug('Terminate signal being sent to process {0} on node {1}'.format(cap_pid, host))

duration = int(time.time()) - start_ts
log_info('Captured for {0} seconds'.format(duration))


# todo: need to check that captures are terminated before calling fetch_files
if FETCH_CAPTURES:
    for host in HOSTS:
        fetch_files(host, HOSTS[host], cap_result[host])

