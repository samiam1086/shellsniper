# module monitors the netstat -pant output for suspicious connections

import os
import subprocess

def make_red(indata):
    color_RED = '\033[91m'
    color_reset = '\033[0m'
    return '{}{}{}'.format(color_RED, indata, color_reset)

def make_blue(indata):
    color_BLU = '\033[94m'
    color_reset = '\033[0m'
    return '{}{}{}'.format(color_BLU, indata, color_reset)

def conn_guard(stop_attack, block_offenders):
    print('Starting conn_guard stop_attack:{} block_offenders:{}'.format(stop_attack, block_offenders))
    shell_list = ['sh', '/bin/sh', 'bash', '/bin/bash', 'cmd', 'powershell', 'pwsh', 'ash', 'bsh', 'csh', 'ksh', 'zsh', 'pdksh', 'tcsh', 'mksh', 'dash', 'telnet', 'nc', 'netcat']
    suspicious_remote_ports = ['9000', '9001', '4444', '1337', '31337']
    reported_pids = []
    while True:
        proc = subprocess.getoutput('sudo netstat -pant') # gets the output of netstat -pant
        proc = proc.split('\n') # goes from a single string to a list

        # Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
        for item in proc[2:]: #proc[2:] skips the first 2 items since they are just data
            item = ' '.join(item.split()) # go from multiple whitespaces to one
            item = item.split(' ')  # from string to list removing whitespace

            try:
                if item[5] == 'ESTABLISHED' and item[6] != '-': # if we have an established connection
                    split_item6 = item[6].split('/')
                    if split_item6[1] in shell_list: # if the program running that connection is sus
                        if block_offenders and stop_attack:
                            os.system('sudo kill -9 {} 2>/dev/null'.format(split_item6[0])) # kill the process
                            os.system('sudo iptables -A INPUT -s {} -j DROP'.format(item[4].split(':')[0])) # ban their ip
                            print('{}: There is a remote connection with {} on PID {} to remote host {}. Terminating PID {}.. Blocking IP {}'.format(make_blue('Conn-Guard'), make_red(split_item6[1]), make_red(split_item6[0]), make_red(item[4].split(':')[0]), make_red(split_item6[0]), make_red(item[4].split(':')[0])))
                            print('To unblock the host run sudo iptables -D INPUT -s {} -j DROP'.format(item[4].split(':')[0]))
                            continue
                        elif stop_attack:
                            os.system('sudo kill -9 {} 2>/dev/null'.format(split_item6[0]))
                            print('{}: There is a remote connection with {} on PID {} to remote host {}. Terminating PID {}'.format(make_blue('Conn-Guard'), make_red(split_item6[1]), make_red(split_item6[0]), make_red(item[4].split(':')[0]), make_red(split_item6[0])))
                            continue
                        else:
                            if split_item6[0] not in reported_pids:
                                print('{}: There is a remote connection with {} on PID {} to remote host {}'.format(make_blue('Conn-Guard'), make_red(split_item6[1]), make_red(split_item6[0]), make_red(item[4].split(':')[0])))
                                reported_pids.append(split_item6[0])
                                continue


                    if item[4].split(':')[1] in suspicious_remote_ports:
                        split_item6 = item[6].split('/')
                        if block_offenders and stop_attack:
                            os.system('sudo kill -9 {} 2>/dev/null'.format(split_item6[0]))  # kill the process
                            os.system('sudo iptables -A INPUT -s {} -j DROP'.format(item[4].split(':')[0]))  # ban their ip
                            print('Conn-Guard: There is a remote connection with PID {} to remote host {} on a suspicious port. Terminating PID {}.. Blocking IP {}'.format(make_red(split_item6[0]), make_red(item[4]), make_red(split_item6[0]), make_red(item[4].split(':')[0])))
                            print('To unblock the host run sudo iptables -D INPUT -s {} -j DROP'.format(item[4].split(':')[0]))
                            continue
                        elif stop_attack:
                            os.system('sudo kill -9 {} 2>/dev/null'.format(split_item6[0]))
                            print('Conn-Guard: There is a remote connection with PID {} to remote host {} on a suspicious port Terminating PID {}'.format(make_red(split_item6[0]), make_red(item[4]), make_red(split_item6[0])))
                            continue
                        else:
                            if split_item6[0] not in reported_pids:
                                print('Conn-Guard: There is a remote connection with PID {} to remote host {} on a suspicious port'.format(make_red(split_item6[0]), make_red(item[4])))
                                reported_pids.append(split_item6[0])
                                continue

            except BaseException as e:
                print(str(e))
                print(item)
