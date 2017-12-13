#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# MS security guidance parser
# Query the CVE infos to https://portal.msrc.microsoft.com/ja-jp/security-guidance and write to csv file.

import csv
import json
import sys
import time
import urllib.request

URL = "https://portal.msrc.microsoft.com/api/security-guidance/ja-JP/CVE/"
OUTPUT_FILE = "ms_security_advisory.csv"


def send_http_request(url, cve):
    """
    Send http request.
    Return json as cve infomations.
    """
    print(url + cve)
    try:
        req = urllib.request.Request(url + cve)
        html = urllib.request.urlopen(req)
        json_dict = json.loads(html.read().decode('utf-8'))
    except:
        json_dict = None
    return json_dict


def extract_value_from_dict(json_dict):
    """
    Extract CVE informations from dict.
    Return the list of file informations.
    cveNumber | cveTitle | affectedProducts -> name | description | exploited and publiclyDisclosed | affectedProducts -> impact | affectedProducts -> severity | affectedProducts -> vectorString
    """
    cve_info = []
    products = []

    try:
        cve_info.append(json_dict['cveNumber'])
        cve_info.append(json_dict['cveTitle'])
        for i in range(len(json_dict['affectedProducts'])):
            products.append(json_dict['affectedProducts'][i]['name'])
        cve_info.append(products)
        cve_info.append(json_dict['description'])
        if (json_dict['exploited'] == 'あり') and (json_dict['publiclyDisclosed'] == 'あり'):
            cve_info.append('一般に公開/あり')
        elif (json_dict['exploited'] == 'あり') and (json_dict['publiclyDisclosed'] == 'なし'):
            cve_info.append('あり')
        elif (json_dict['exploited'] == 'なし') and (json_dict['publiclyDisclosed'] == 'あり'):
            cve_info.append('一般に公開')
        else:
            cve_info.append('なし')

        tmp = json_dict['affectedProducts'][0]['severity'] + ':' + json_dict['affectedProducts'][0]['impact']
        cve_info.append(tmp)
        cve_info.append(json_dict['affectedProducts'][0]['vectorString'])

        return cve_info
    except:
        return "N/A"


def export_to_csv(csv_info):
    table_headline = ['cveNumber', 'cveTitle', 'name', 'description', 'exploited and publiclyDisclosed', 'impact and severity', 'vectorString']

    with open(OUTPUT_FILE, 'a', newline='', encoding='utf-16') as f:
        writecsv = csv.writer(f, dialect='excel', delimiter='\t', quoting=csv.QUOTE_ALL)
        writecsv.writerow(table_headline)
        for i in (range(len(csv_info))):
            writecsv = csv.writer(f, dialect='excel', delimiter='\t', quoting=csv.QUOTE_ALL)
            writecsv.writerow(csv_info[i])


def main():
    if len(sys.argv) != 2:
        print('usage:\n\tpython3 ms_security_advisory.py [cve_list.txt]\n')
        exit(0)

    CVE_LIST = sys.argv[1]
    csv_info = []
    with open(CVE_LIST, 'r') as f:
        cve_list = f.readlines()
    for csv in cve_list:
        print('Now processing ' + str(cve_list.index(csv) + 1) + '/' + str(len(cve_list)) + '...')
        tmp = []
        csv = csv.rstrip('\n')
        json_dict = send_http_request(URL, csv)
        if json_dict is not None:
            tmp = extract_value_from_dict(json_dict)
            csv_info.append(tmp)
    export_to_csv(csv_info)

    print('FINISHED!!!')


if __name__ == '__main__':
    main()
