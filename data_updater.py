import os
import ckanapi
from time import sleep
import re
from datetime import datetime
import bcrypt
import getpass
from Cryptodome.Cipher import AES
import json


DATASET_TEMPLATE = "https://data.gov.ua/api/3/action/package_show?id={id:s}"
UPDATE_TEMPLATE = ""
YEAR_RE = re.compile("\d{4}")
UPDATE_FOLDER = "OPENDATA_UPDATE"
NUMBER_RE = re.compile("\d+")
PERIOD_RE = re.compile("[qm]?\d+[qm]?[_\.]")
RE_PART = "(_.?\d+.*)+[_\.]"
TOKEN_FILE = "token.dat"
SERVER = "https://data.gov.ua"
DATASETS_FILE = "datasets.json"


def to_monthes(s):
    number = int(NUMBER_RE.search(s).group())
    if "q" in s:
        multiplier = 3
    if "m" in s:
        multiplier = 1
    new_monthes = str(number * multiplier)
    if len(new_monthes) == 1:
        new_monthes = "0" + new_monthes
    return new_monthes
    
def datetime_from_filename(s):
    period_matched = PERIOD_RE.findall(s)
    period_matched = [to_monthes(p) if "q" in p or "m" in p else p.replace('.',"").replace("_","") for p in period_matched]
    try:
        if len(period_matched[-1]) == 4:
            if len(period_matched) == 3:
                d = "-".join(period_matched[-1::-1])
            elif len(period_matched) == 2:
                d = "-".join(period_matched[-1::-1] + ['01'])
            #elif len(period_matched) == 1:
            #    d = "-".join(period_matched + ['01'] + ['01'])
        elif len(period_matched[0]) == 4:
            if len(period_matched) == 3:
                d = "-".join(period_matched)
            elif len(period_matched) == 2:
                d = "-".join(period_matched + ['01'])
            #elif len(period_matched) == 1:
            #    d = "-".join(period_matched + ['01'] + ['01'])
        return datetime.strptime(d, "%Y-%m-%d")
    except Exception:
        print("Неправильний формат дати у рядку", s)

def is_update_newer(current_file, update_file):
    return datetime_from_filename(update_file) > datetime_from_filename(current_file)

def newest_file(files):
    if len(files) > 1:
        datetimes = list(map(datetime_from_filename, files))
        for i in range(len(files)):
            if datetimes[i] == max(datetimes):
                return files[i]
    else:
        return files[0]

def upload_update(resource_id, file_):
    print("Файл",file_, "вантажиться...")
    files = [('upload', open(file_, "rb"))]
    r = ckan.action.resource_update(id=resource_id,upload=open(file_,'rb'))
    print(r)

password = getpass.getpass("Введіть пароль до файла з ключем: ")
key = bcrypt.kdf(password = password.encode(), salt = b"salt", desired_key_bytes = 32, rounds = 100)

file_in = open(TOKEN_FILE, "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
token = data.decode("UTF-8")
ckan = ckanapi.RemoteCKAN(SERVER, apikey = token, user_agent = "minenergo autoupdate")

with open(DATASETS_FILE, "r") as dsetf:
    datasets_ids = json.load(dsetf)

update_files = {} 
for root, dirs, files in os.walk(UPDATE_FOLDER):
    for f in files:
        update_files[f] = os.path.join(root, f)

resources_data = {}
for d in datasets_ids:
    sleep(1)
    resources_data[d] = {}
    dataset_info = ckan.action.package_show(id = d)
    #dataset_info = requests.get(DATASET_TEMPLATE.format(id = d), headers = {"Authorization":token}).json()
    resources = dataset_info['resources']
    for r in resources:
        f = r['url'].split('/')[-1]
        if YEAR_RE.search(f):
            resources_data[d][r['id']] = {}
            resources_data[d][r['id']]['file'] = f
            resources_data[d][r['id']]['desc'] = " — ".join([dataset_info['title'], r['description']])
            fl_without_ext = f.rsplit(".", maxsplit = 1)[0]
            parts = fl_without_ext.split("_")
            parts = [p for p in parts if not NUMBER_RE.search(p)]
            before_extension = "_".join(parts).replace(".", "\.")
            reg = before_extension + RE_PART + f.rsplit(".", maxsplit = 1)[1]
            resources_data[d][r['id']]['re'] = reg
            updates = []
            for k in update_files.keys():
                if re.fullmatch(reg, k):
                    if is_update_newer(f, k):
                        updates.append(k)
            if len(updates) > 0:
                to_upload = update_files[newest_file(updates)]
                upload_update(r['id'], to_upload)

ckan.close()