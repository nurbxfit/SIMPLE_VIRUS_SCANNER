import hashlib
import requests
import json
import sys
import os
import argparse


API_KEY = 'REPLACE WITH YOUR VIRUSTOTAL API KEY'
URL = 'https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}'

#argument parser
parsed = argparse.ArgumentParser(
    description='scan file using virus total API'
)

# comand line argument
parsed.add_argument(
    '-p',
    metavar='path',
    type=str,
    help='path to the file'
)
args = parsed.parse_args()

FILE_PATH = args.p


if not os.path.exists(FILE_PATH):
    print('The path is Invalid')
    sys.exit()

fn = open(FILE_PATH,"rb").read()
hashed_fn = hashlib.md5(fn).hexdigest()
print('md5sum: {}'.format(hashed_fn))

print('--------------------------------------')
print('Retriving VirusTotal File scan report...')
print('Sending md5 hash..: {}'.format(hashed_fn))
res = requests.get(URL.format(API_KEY,hashed_fn))
json_res = json.loads(res.text)

#respon_code : 1 means success
if (json_res['response_code']):
    scan_id     = json_res['scan_id']
    scan_msg    = json_res['verbose_msg']
    scan_link   = json_res['permalink']
    positive    = json_res['positives']
    scan_total  = json_res['total']
    print(f'{scan_msg}\nScan_id: {scan_id}\n\nlink: {scan_link}\n\nResult:{positive}/{scan_total}')





