import threading
import os, sys
import argparse
from wgcore.limitssh import limit_ssh
from wgcore.procwatch import proc_watch
from wgcore.connectionguard import conn_guard

cwd = os.path.abspath(os.path.dirname(__file__))

def parse_config():
    config = {}
    conf_keys = config.keys()
    try:
        with open('watchguard.conf', 'r') as f:
            conf_data = f.read().split('\n')
    except FileNotFoundError:
        print('Error watchguard.conf cannot be located')
        sys.exit(1)
    else:
        for item in conf_data:
            if item.replace(' ', '') != '':
                item = item.split('=')
                if item[1] == 'True':
                    config[item[0].replace(' ', '')] = True
                elif item[1] == 'False':
                    config[item[0].replace(' ', '')] = False
                else:
                    print('Invalid data at {}'.format(item))
                    sys.exit(1)

    return config

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Must be run as sudo")
        sys.exit(1)

    config = parse_config()
    
    whitelisted_users = input('Enter a list of usernames seperated by commas to whitelist ex kali,test\n(NOTE SINCE WE ARE RUNNING THIS AS ROOT YOU MUST INCLUDE root IN THE LIST OR YOU GET KICKED OFF THE MACHINE): ')
    whitelisted_ips = input("Enter a list of IPS seperated by commas to whitelist ex 10.10.10.2\n(NOTE SINCE WE ARE CONNECTING TO THIS MACHINE WITHOUR SSH CONNECTION WHITELIST YOUR INTERNAL IP): ")

    thread_list = []
    try:
        if config['run-ssh-guard'] :
            ssh_guard_thread = threading.Thread(target=limit_ssh, args=(config['ssh-guard-blockoffenders'], whitelisted_users, whitelisted_ips, ))
            thread_list.append(ssh_guard_thread)
    
        if config['run-proc-watch']:
            proc_watch_thread = threading.Thread(target=proc_watch, args=(config['proc-watch-stopattack'],))
            thread_list.append(proc_watch_thread)
    
        if config['run-conn-guard']:
            conn_guard_thread = threading.Thread(target=conn_guard, args=(config['conn-guard-stopattack'], config['conn-guard-blockoffenders'],))
            thread_list.append(conn_guard_thread)
    
        for thread in thread_list:
            thread.start()
    except KeyError as e:
        print(str(e))
        print("Error you are likely missing an item from the config")
