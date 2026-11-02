#!/usr/bin/python3 -I
"""Make a distributable install kit. Never bundle device credentials or profiles."""
import argparse
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile


def main():
    parser=argparse.ArgumentParser(description='Собрать архив установщика и локальных DEB без секретов')
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--sqlcipher-package', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
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
        root.mkdir(mode=0o755)
        installer=Path(__file__).resolve().with_name('install-dlp.py')
        for source in [installer,*sources]:
            shutil.copyfile(source, root/source.name)
            (root/source.name).chmod(0o755 if source==installer else 0o644)
        (root/'START.txt').write_text('''DLP Lab — установка агента

1. Распакуйте архив на целевой Debian12/13 совместимой версии.
2. Администратор передаёт индивидуальный central-agent.json (chmod600)
   и публичный CA central-ca.crt в этот каталог. Это НЕ admin.json!
3. Терминал в каталоге dlp-install:
   sudo ./install-dlp.py --check
   sudo ./install-dlp.py
   При нескольких пользователях добавьте --user ИМЯ.
   Без сервера — явно --local-only; существующий отправщик не отключается.
   Для административной автоматизации есть --yes.

Клиенты Telegram/Signal устанавливаются заранее. Для нестандартного пути
используйте --telegram /путь/к/Telegram и --signal /путь/к/Signal.
На уже настроенной машине пути заново не задавайте. Для sudo из root-сессии
при неоднозначном выборе пользователя нужен --user.

Установщик не загружает пакеты DLP из интернета, не меняет настройки клиента,
не перезаписывает регистрацию. Apt получает зависимости из настроенных репозиториев.
Существующая политика сохраняется. При ошибке возможна частичная установка:
автоматического отката нет. Исправьте причину и повторите; не удаляйте очередь.

После завершения: monitor_started в журнале files, тестовое прикрепление,
событие и диагностика устройства в панели. Текст/локальные базы требуют
отдельной настройки пользовательского сеанса. Поддерживается один desktop UID.

SHA256SUMS проверяет целостность комплекта, но НЕ заменяет доверенную подпись
или проверку происхождения архива. Получайте комплект от своего администратора.
''', encoding='utf-8')
        with (root/'SHA256SUMS').open('w') as out:
            for p in sorted(root.iterdir()):
                if p.name!='SHA256SUMS': out.write(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
        with tarfile.open(args.output,'w:gz') as archive:
            archive.add(root,arcname='dlp-install')
    print(args.output.resolve())


if __name__=='__main__': main()
