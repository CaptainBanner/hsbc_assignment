import re
import requests
import json


def get_urlscan_ind(verdict_api):
    verdict_api_response = requests.get(verdict_api)
    verdict_dict = (json.loads(verdict_api_response.text))['verdicts']
    malicious_ind = False
    if verdict_dict['overall']['malicious'] or verdict_dict['engines']['maliciousTotal'] or verdict_dict['community']['votesMalicious']:
        malicious_ind = True
    return malicious_ind


def urlscan(Ip):
    data = {
        "url": Ip,
        "visibility": "private",
        "tags": "malicious"
    }
    headers = {
        'API-Key': 'cbab9d23-7028-4d33-8242-7aebc4019c66',
        'Content-Type': 'application/json'
    }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    mal_ind = json.loads(response.text)['url']
    return response.json(), response.status_code


def virusscanip(Ip):
    headers = {
        'x-apikey': '0cfe4924eb375231207eed34c77446c3f0bf6b3517498ef18d00ac2f67948d7e',
        'Content-Type': 'application/json'
    }
    virus_scan = requests.get('https://www.virustotal.com/api/v3/ip_addresses/' + Ip, headers=headers)
    if virus_scan.status_code == 200:
        temp_dict = json.loads(virus_scan.text)['data']['attributes']['last_analysis_stats']

        if temp_dict['malicious'] > 0 or temp_dict['suspicious'] > 0:
            malicious = True
        else:
            malicious = False
    else:
        malicious = 'UNKNOWN'
    return virus_scan.json(), virus_scan.status_code, malicious


def virusscandomain(Ip):
    headers = {
        'x-apikey': '0cfe4924eb375231207eed34c77446c3f0bf6b3517498ef18d00ac2f67948d7e',
        'Content-Type': 'application/json'
    }
    virus_scan = requests.get('https://www.virustotal.com/api/v3/domains/' + Ip, headers=headers)

    if virus_scan.status_code == 200:
        temp_dict = json.loads(virus_scan.text)['data']['attributes']['last_analysis_stats']
        if temp_dict['malicious'] > 0 or temp_dict['suspicious'] > 0:
            malicious = True
        else:
            malicious = False
    else:
        malicious = 'UNKNOWN'
    return virus_scan.json(), virus_scan.status_code, malicious


def validate_ip( Ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    if re.search(regex, Ip):
        return True
    return False


def validate_domain(domain):
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"

    if re.search(regex, domain):
        return True
    return False