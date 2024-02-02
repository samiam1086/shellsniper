#module only allows access to ssh from whitelisted ips and users

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

def limit_ssh(block_offenders, whitelisted_users, whitelisted_ips):
    print('Starting ssh_guard block_offenders:{}'.format(block_offenders))
    default_ips = [':0', '::1', '127.0.0.1', 'localhost', '-'] # some defaults that we dont want to kill
    default_users = ['root']

    if whitelisted_ips == None:
        whitelisted_ips = ''
    if whitelisted_users == None:
        whitelisted_users = ''

    if whitelisted_users.find(',') != -1: # convert their string to a list but if they just give one thats ok too
        whitelisted_users = whitelisted_users.split(',')
    else:
        whitelisted_users = [whitelisted_users]

    if whitelisted_ips.find(',') != -1:# convert their string to a list but if they just give one thats ok too
        whitelisted_ips = whitelisted_ips.split(',')
    else:
        whitelisted_ips = [whitelisted_ips]

    for ip in default_ips: # add our default ips to whitelisted
        whitelisted_ips.append(ip)

    for user in default_users: # add our default ips to whitelisted
        whitelisted_users.append(user)

    while True:

        dat = subprocess.getoutput('w').split('\n') # get a list of everyone whose sshed in
        # 0=username 1=TTY 2=RemoteIP
        for item in dat[2:]: # dat[2:] skips the first two items since they are not relevant
            if item != '': # make sure the string is not empty
                item = ' '.join(item.split()) # go from multiple whitespaces to one
                item = item.split(' ') # from string to list removing whitespace

                if item[0] not in whitelisted_users: # item[0] will be the username
                    os.system('sudo killall -u {} 2>/dev/null'.format(item[0]))
                    print('{}: Non-Whitelisted account {} connected from {} and their connection was terminated'.format(make_blue('SSH-Guard'), make_red(item[0]), make_red(item[2])))
                    if block_offenders:
                        os.system('sudo iptables -A INPUT -s {} -j DROP'.format(item[2]))
                        print('{}: Blocking IP address {} to unblock the IP run: sudo iptables -D INPUT -s {} -j DROP'.format(make_blue('SSH-Guard'), make_red(item[2]), item[2]))  # block the ip through iptables
                        continue
                    else:
                        continue

                if item[2] not in whitelisted_ips: # itemp[2] will be the from address (IP)
                    dat1 = subprocess.getoutput('sudo ps -aux | grep ssh | grep \'{}@{}\' | grep -v \'grep\''.format(item[0], item[1])) # if the ip is not whitelisted we need to get its pid
                    if dat1 != '':
                        dat1 = ' '.join(dat1.split()) # go from multiple whitespaces to one
                        dat1 = dat1.split(' ') # from string to list removing whitespace
                        os.system('sudo kill -9 {} 2>/dev/null'.format(dat1[1])) # dat1[1] is the pid
                        print('{}: Non-Whitelisted IP {} was found using account {} on PID {} was terminated'.format(make_blue('SSH-Guard'), make_red(item[2]), make_red(dat1[0]), make_red(dat1[1])))
                        if block_offenders:
                            print('{}: Blocking IP address {} to unblock the IP run: sudo iptables -D INPUT -s {} -j DROP'.format(make_blue('SSH-Guard'), make_red(item[2]), item[2])) # block the ip through iptables
                            os.system('sudo iptables -A INPUT -s {} -j DROP'.format(item[2]))
