import requests
import json
import locale
import sys

ctl_log = requests.get('https://www.gstatic.com/ct/log_list/v3/log_list.json').json()

total_certs = 0

human_format = lambda x: locale.format_string('%d', x, grouping=True)

for operator in ctl_log['operators']:
    
    for log in operator['logs']:
        log_url = log['url']
        # print(log_url)
        try:
            log_info = requests.get('{}/ct/v1/get-sth'.format(log_url), timeout=3).json()
            print(log_info['tree_size'])

            total_certs += int(log_info['tree_size'])
        except:
            continue

        print("{} has {} certificates".format(log_url, human_format(log_info['tree_size'])))

print("Total certs -> {}".format(human_format(total_certs)))
