#!/usr/bin/python3 -I
"""Combine an existing per-device registration and public CA, never an admin token."""
import argparse
import importlib.util
import json
import os
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description='Создать индивидуальный профиль для dlp-setup')
    p.add_argument('--registration',type=Path,required=True)
    p.add_argument('--ca',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    spec=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install-dlp.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    data=json.dumps({'registration':m.registration(m.read_file(args.registration,private=True)),
                     'ca':m.read_file(args.ca).decode('ascii')}).encode()
    m.connection(data)
    fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)
    print('Профиль создан. Передайте его только указанному устройству; не публикуйте.')

if __name__=='__main__':main()
