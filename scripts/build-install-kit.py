#!/usr/bin/python3 -I
"""Make a distributable install kit. Optional private per-device kit; never bundle administrator tokens or profiles."""
import argparse
import hashlib
import importlib.util
import os
import ssl
from pathlib import Path
import shutil
import tarfile
import tempfile


def main():
    parser=argparse.ArgumentParser(description='Собрать общий или индивидуальный установочный комплект')
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--sqlcipher-package', type=Path)
    parser.add_argument('--registration', type=Path, help='Private per-device central-agent.json, never admin.json')
    parser.add_argument('--ca', type=Path, help='Public CA for the private kit')
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    identity = certificate = None
    if bool(args.registration) != bool(args.ca):
        parser.error('--registration и --ca задаются вместе')
    if args.registration:
        spec=importlib.util.spec_from_file_location('kit_installer',Path(__file__).with_name('install-dlp.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        identity=module.read_file(args.registration,private=True)
        module.registration(identity)
        certificate=module.read_file(args.ca)
        ssl.create_default_context(cadata=certificate.decode('ascii'))
    sources=[args.package]+([args.sqlcipher_package] if args.sqlcipher_package else [])
    if not args.package.name.startswith('dlp-lab_') or any(p.suffix != '.deb' or not p.is_file() for p in sources):
        parser.error('Укажите существующие DEB; пакет агента должен называться dlp-lab_*.deb')
    if args.sqlcipher_package and not args.sqlcipher_package.name.startswith('libsqlcipher1_'):
        parser.error('Дополнительный пакет должен называться libsqlcipher1_*.deb')
    if args.output.exists():
        parser.error('Выходной архив уже существует')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)/'dlp-install'
        root.mkdir(mode=0o700)
        installer=Path(__file__).resolve().with_name('install-dlp.py')
        for source in [installer,*sources]:
            shutil.copyfile(source, root/source.name)
            (root/source.name).chmod(0o755 if source==installer else 0o644)
        (root/'install.sh').write_text('#!/bin/sh\nset -eu\nCDPATH= cd -- "$(dirname -- "$0")"\nexec /usr/bin/python3 -I ./install-dlp.py "$@"\n')
        (root/'install.sh').chmod(0o755)
        if identity is not None:
            (root/'central-agent.json').write_bytes(identity)
            (root/'central-agent.json').chmod(0o600)
            (root/'central-ca.crt').write_bytes(certificate)
        (root/'START.txt').write_text("""DLP — установочный комплект

Распакуйте и выполните в каталоге dlp-install:
    sudo ./install.sh

Это одна команда: проверки, установка пакетов, настройка и запуск служб.
Если подключение не включено в комплект, администратор кладёт рядом
central-agent.json (0600) и central-ca.crt. Для обновления существующей машины
регистрация сохраняется. При неоднозначном выборе добавьте --user ИМЯ.
Для проверки без установки: sudo ./install.sh --check.

Комплект с регистрацией предназначен только одной машине. Не публикуйте его
и не отправляйте другим пользователям. Это не токен администратора сервера.
Telegram должен быть установлен заранее; Signal подключается дополнительно.
Пакет должен соответствовать Debian12/13. Изменения политики сохраняются.
Сеансовый контроль запускается системой; доступность AT-SPI проверяется отдельно.
После установки проверьте событие устройства в центральной панели.
SHA256SUMS проверяет целостность, но не заменяет доверие к источнику комплекта.
""", encoding='utf-8')
        with (root/'SHA256SUMS').open('w') as out:
            for p in sorted(root.iterdir()):
                if p.name!='SHA256SUMS': out.write(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:
            with tarfile.open(fileobj=stream,mode='w:gz') as archive:
                archive.add(root,arcname='dlp-install')
    print(args.output.resolve())


if __name__=='__main__': main()
