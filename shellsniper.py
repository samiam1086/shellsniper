import threading
import os, sys
import argparse
from sscore.limitssh import limit_ssh
from sscore.procwatch import proc_watch
from sscore.connectionguard import conn_guard

cwd = os.path.abspath(os.path.dirname(__file__))

def parse_config():
    config = {}
    conf_keys = config.keys()
    try:
        with open('{}/shellsniper.conf'.format(cwd), 'r') as f:
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
    parser = argparse.ArgumentParser(add_help=True, description='')
    parser.add_argument('-wu', action='store', required=True, help='Users to whitelist for ssh seperated by commas ex: kali,root')
    parser.add_argument('-wi', action='store', help='IPs to whitelist for ssh seperated by commas ex: 10.10.10.1,10.10.20.1')

    print('\n( -_•)▄︻デ══━一\t\tnetcat\n')

    config = parse_config()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    thread_list = []
    try:
        if config['run-ssh-guard'] :
            ssh_guard_thread = threading.Thread(target=limit_ssh, args=(config['ssh-guard-blockoffenders'], options.wu, options.wi, ))
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
        sys.exit(1)
