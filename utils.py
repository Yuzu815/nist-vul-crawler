import random
import time
import json
import requests
from fake_useragent import UserAgent

fake_ua = UserAgent()


def session_generator():
    session = requests.Session()
    session.headers.update({
        "User-Agent": fake_ua.chrome,
        "Referer": "https://nvd.nist.gov"
    })
    return session


def send_request(uri: str):
    response = None
    while response is None or response.status_code != 200:
        try:
            time.sleep(random.randint(100, 500) / 1000)
            session = session_generator()
            response = session.get(uri)
        except Exception as e:
            print('Log: ' + str(e))
            continue
    return response


def write_to_jsonl(filepath: str, data: list, debug_mode=False):
    with open(filepath, 'a') as f:
        for item in data:
            for item_id in range(len(item['source'])):
                if item['source_status'][item_id]['vul_flag'] == 1 and \
                   item['source_status'][item_id]['language'] in ['C', 'C++', 'Python', 'Java']:
                    f.write(json.dumps({
                        'input': item['source'][item_id],
                        'output': 'This program snippet has a vulnerability.' + item['explanation']
                    }) + '\n')
    if debug_mode:
        with open('Debug.jsonl', 'a') as f:
            for item in data:
                f.write(json.dumps(item) + '\n')


def write_to_file(filepath: str, content: str):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
