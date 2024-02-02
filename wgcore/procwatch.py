# module monitors ps for suspicious commands being run

import os, re
import subprocess


def make_red(indata):
    color_RED = '\033[91m'
    color_reset = '\033[0m'
    return '{}{}{}'.format(color_RED, indata, color_reset)

def proc_watch(stop_attack):
    print('Starting proc_watch stop_attack:{}'.format(stop_attack))
    ipv4_regex = r'((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}'
    port_regex = '[0-9]*'
    shell_regex = r'\S*'
    reverse_shells_dict = {
        'Socket': 'Socket Connection (Likely a Reverse Shell)',
        'socket': 'Socket Connection (Likely a Reverse Shell)',
        '/dev/tcp/{}/{}'.format(ipv4_regex, port_regex): 'TCP Reverse Shell',
        '/dev/udp/{}/{}'.format(ipv4_regex, port_regex): 'UDP Reverse Shell',
        '/inet/tcp/0/{}/{}'.format(ipv4_regex, port_regex): 'inet Reverse Shell',
        '/inet/udp/0/{}/{}'.format(ipv4_regex, port_regex): 'inet Reverse Shell',
        'nc {} {}'.format(ipv4_regex, port_regex): 'nc Reverse Shell',
        'nc {} {} {}'.format(shell_regex, ipv4_regex, port_regex): 'nc Reverse Shell',
        'nc {} {} {} {}'.format(shell_regex, shell_regex, ipv4_regex, port_regex): 'nc Reverse Shell',
        'netcat {} {}'.format(ipv4_regex, port_regex): 'netcat Reverse Shell',
        'netcat {} {} {}'.format(shell_regex, ipv4_regex, port_regex): 'netcat Reverse Shell',
        'netcat {} {} {} {}'.format(shell_regex, shell_regex, ipv4_regex, port_regex): 'netcat Reverse Shell',
        'ncat {} {}'.format(ipv4_regex, port_regex): 'ncat Reverse Shell',
        'ncat {} {} {}'.format(shell_regex, ipv4_regex, port_regex): 'ncat Reverse Shell',
        'ncat {} {} {} {}'.format(shell_regex, shell_regex, ipv4_regex, port_regex): 'ncat Reverse Shell',
        'curl -Ns telnet://{}:{}'.format(ipv4_regex, port_regex): 'curl Reverse Shell',
        'rcat connect -s {} {} {}'.format(shell_regex, ipv4_regex, port_regex): 'rustcat Reverse Shell',
        r'php -r \${}=fsockopen\("{}",{}\);'.format(shell_regex, ipv4_regex, port_regex): 'PHP Reverse Shell',
        'socat TCP:{}:{} EXEC:{}'.format(ipv4_regex, port_regex, shell_regex): 'socat Reverse Shell',
        'telnet {} {}'.format(ipv4_regex, port_regex): 'Telnet Reverse Shell'
    }
    reported_pids = []
    rsd_keys = reverse_shells_dict.keys()
    while True:
        # USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
        dat = subprocess.getoutput('sudo ps -aux')
        dat = dat.split('\n')

        for item in dat[1:]: # skips the first item in dat
            item = ' '.join(item.split())  # go from multiple whitespaces to one from 'this      that    there' to 'this that there'
            item = item.split(' ')  # from string to list removing whitespace from 'this that there' to ['this', 'that', 'there']
            if item != '': # ensure that the item is not blank
                if item[6] != '?': # check to ensure that we are not wasting time with system processes and you cannot do this in the subprocesses command since grep -v '?' would allow for a question mark to be added to a reverse sheel to bypass this module
                    command = ' '.join(item[10:]) # gets the command into a single string
                    for regex in rsd_keys: # iterate through each regex
                        if re.search(regex, command): # see if theres a match
                            if stop_attack: # if we are in ips mode
                                os.system('sudo kill -9 {}'.format(item[1])) # kill the process
                                print('Proc-Watch: Process {} was found to match {} with command {} Terminating process'.format(make_red(item[1]), make_red(reverse_shells_dict[regex]), make_red(command)))
                            else:
                                if item[1] not in reported_pids:
                                    print('Proc-Watch: Process {} was found to match {} with command {}'.format(make_red(item[1]), make_red(reverse_shells_dict[regex]), make_red(command)))
                                    reported_pids.append(item[1])
                            break
