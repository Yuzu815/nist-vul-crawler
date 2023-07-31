import os
import socket

import pandas as pd
import socks
from bs4 import BeautifulSoup

from utils import *

# You can set this up here if you need to use a proxy to access the website (Sock5).
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 23333)  # IP and Port
socket.socket = socks.socksocket


def parse_vul_categories(uri: str):
    def parse_links(the_table):
        links_list = []
        for row in the_table.find_all('tr')[1:]:
            links_in_the_row = []
            for cell in row.find_all(['td', 'th']):
                cell_link = cell.find('a')
                if cell_link:
                    links_in_the_row.append(cell_link['href'])
            links_list.extend(links_in_the_row if links_in_the_row else ['Invalid'])
        return [str(item).replace('http', 'https') for item in links_list]

    r = send_request(uri)
    table = BeautifulSoup(r.text, 'html.parser').find('table')
    pd_tables = pd.read_html(str(table))
    if len(pd_tables) != 1:
        return None, None
    else:
        return pd_tables[0], parse_links(table)


def slice_subheading(div):
    result = []
    subheadings = div.find_all("p", class_="subheading")
    for i, subheading in enumerate(subheadings):
        content = subheading.text
        next_content = subheading.next_siblings
        text = ""
        for tag in next_content:
            if tag == subheadings[i + 1] if i + 1 < len(subheadings) else None:
                break
            text += str(tag)
        result.append((content, text))
    return result


def parse_single_cwe_page(uri: str, cwe_id: str):
    parse_result = []
    response = send_request(uri)
    examples_div = BeautifulSoup(response.text, 'html.parser').find('div', id='Demonstrative_Examples')
    if examples_div is None:
        return parse_result
    slice_result = slice_subheading(examples_div)
    for item in slice_result:
        example_id, html_snippet = item
        html_soup = BeautifulSoup(html_snippet, 'html.parser')
        source_snip_div = html_soup.find_all('div', {'class': 'top'})
        source_text_list = []
        for source_item in source_snip_div:
            source_text_list.append(source_item.get_text().strip())
            source_item.decompose()
        source_status_div = html_soup.find_all('div', {'class': 'CodeHead'})
        source_status_list = []
        for source_status_item in source_status_div:
            status_text = source_status_item.get_text()
            vul_flag = 1 if '(bad code)' in status_text else 0
            status_text = status_text.replace('(bad code)', '')
            status_text = status_text.replace('(good code)', '')
            source_status_list.append({
                'vul_flag': vul_flag,
                'language': status_text.replace('Example Language:', '').strip(),
            })
            source_status_item.decompose()
        explanation = html_soup.get_text().strip()
        parse_result.append({
            'source': source_text_list,
            'source_status': source_status_list,
            'cwe_id': cwe_id,
            'example_id': example_id.replace('Example', '').strip(),
            'explanation': explanation,
        })
    return parse_result


if __name__ == '__main__':
    # 1. parse the links of vul categories
    pd_table, links = parse_vul_categories('https://nvd.nist.gov/vuln/categories')
    pd_table.insert(pd_table.shape[1], 'Links', links)
    pd_table.to_csv('nvd_cwe_slice.csv', index=False)

    # 2. parse single cwe
    # We store the content in independent jsonl files, and use them to determine if targets need to be skipped.
    for index, data in pd_table.iterrows():
        print('Fetching {}, {}/{}'.format(data['Name'], index, len(pd_table.axes[0])))
        fetch_data_save_path = os.path.join('fetch_data', '{}.jsonl'.format(data['Name']))
        if os.path.exists(fetch_data_save_path):
            print('Skipped. File is existed.')
            continue
        if data['Links'] == 'Invalid':
            print('Skipped. Link is invalid.')
            continue
        single_result = parse_single_cwe_page(data['Links'], data['Name'])
        write_to_jsonl(fetch_data_save_path, single_result, debug_mode=True)
        time.sleep(1)

    # 3. Merge jsonl
    directory = 'fetch_data'
    output_file = 'dataset.jsonl'

    with open(output_file, 'a') as outfile:
        for filename in os.listdir(directory):
            if filename.endswith('.jsonl'):
                with open(os.path.join(directory, filename), 'r') as infile:
                    for line in infile:
                        data = json.loads(line)
                        json.dump(data, outfile)
                        outfile.write('\n')
