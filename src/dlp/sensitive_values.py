"""Offline value-evidence rules for the experimental hybrid classifier.

They detect exposed values, not whether identifiers are issued or secrets work.
No enforcement or calls to external services.
"""
import re
import unicodedata

MAX_BYTES = 16384
PASSPORT = re.compile(r'паспорт\w*|passport', re.I)
SECRET = re.compile(
    r'парол\w*|password|passphrase|(?:(?:api|access)[_ -]?key)|(?:[a-z]+[_-])?token|'
    r'(?:[a-z]+[_-])?secret|ключ\w*\s+доступа|секрет(?:ная\s+фраза|\s+для\s+входа|\s+входа)?|'
    r'ключ\w*\s+для\s+API|одноразовый\s+код|(?:резервный\s+)?код\s+(?:входа|восстановления|аутентификации)|one.time\s+login\s+code|bearer', re.I)
FINANCE = re.compile(
    r'зарплат\w*|заработн\w*\s+плат\w*|оклад\w*|преми\w*|отпускн\w*|'
    r'компенсаци\w*|пособи\w*|гонорар\w*|вознаграждени\w*|поступлени\w*|(?:личн\w*\s+)?доход\w*|'
    r'долг\w*|задолженност\w*|кредит\w*|займ\w*|за[её]м\w*|'
    r'начислен\w*|начислено|удержано|выплат\w*|перечислен\w*|'
    r'выписк\w*|остаток|баланс|salary|payroll|income|debt|loan|balance|overdue', re.I)
INTERNAL = re.compile(r'внутренн\w*|закрыт\w*|непубличн\w*|неопубликован\w*|конфиденциальн\w*|internal', re.I)
BUSINESS = re.compile(r'прибыл\w*|выручк\w*|себестоимост\w*|марж\w*|затрат\w*|расход\w*|расхождени\w*|цен\w*|скидк\w*|бюджет\w*|revenue|profit', re.I)
PUBLIC = re.compile(r'публичн\w*|опубликован\w*|общедоступн\w*|ваканси\w*|прайс|реклам\w*', re.I)
MONEY = re.compile(r'\d[\d\s.,]*\s*(?:руб\w*|₽|RUB|USD|EUR|доллар\w*|евро|тысяч\w*|млн|%)|(?:RUB|USD|EUR|₽|\$)\s*\d[\d.,]*', re.I)
ACCOUNT = re.compile(r'карт\w*|сч[её]т\w*|реквизит\w*|card|account', re.I)


def normalized(text):
    if len(text.encode()) > MAX_BYTES:
        raise ValueError('ml_text_limit')
    return unicodedata.normalize('NFKC', text)


def number_windows(text, cue, patterns):
    """Adjacent groups, ignoring only bounded separators/field names."""
    for m in cue.finditer(text):
        window = text[max(0,m.start()-30):m.end()+180]
        groups=list(re.finditer(r'(?<!\d)\d+(?!\d)', window))
        for i in range(len(groups)):
            for shape in patterns:
                subset=groups[i:i+len(shape)]
                if len(subset)!=len(shape) or [len(g[0]) for g in subset]!=list(shape):
                    continue
                if any(b.start()-a.end()>45 for a,b in zip(subset,subset[1:])):
                    continue
                return True
    return False


def value_evidence(text):
    text=normalized(text)
    strong=set(); weak=set()
    if number_windows(text,PASSPORT,[(10,),(4,6),(2,2,6),(9,),(2,7)]):
        strong.add('passport')
    if number_windows(text,ACCOUNT,[(16,),(4,4,4,4),(20,),(5,5,5,5)]):
        strong.add('financial')
    # Evaluate clauses independently so a public price elsewhere does not mask
    # a private salary. Public wording must be a standalone word, not НЕпубличный.
    for clause in re.split(r'[;\n]|(?<=[.!?])\s+',text):
        money=bool(MONEY.search(clause))
        # Payroll amounts often omit currency units.
        if re.search(r'оклад\w*|преми\w*|начислено|удержано',clause,re.I) and re.search(r'\b\d{4,}\b',clause):
            money=True
        public=bool(re.search(r'\b(?:публичн\w*|опубликован\w*|общедоступн\w*|ваканси\w*|прайс|реклам\w*)',clause,re.I))
        if money and not public:
            if FINANCE.search(clause) or (INTERNAL.search(clause) and BUSINESS.search(clause)):
                strong.add('financial')
            elif BUSINESS.search(clause) and re.search(r'наша|наши|договора|финансового|служебная|директора|переговор',text,re.I):
                weak.add('financial')
    # Header may precede a structured amount line (payroll table).
    if FINANCE.search(text) and MONEY.search(text) and '\n' in text and not PUBLIC.search(text):
        weak.add('financial')
    for m in SECRET.finditer(text):
        tail=text[m.end():m.end()+110]
        # Candidate placeholders are removed before value testing, without
        # suppressing a second, genuinely present value in the same message.
        tail=re.sub(r'\$\{[^}]*\}|\[[^]]*\]|<[^>]*>|\*{2,}', ' ',tail)
        for token in re.findall(r'[A-Za-z0-9][A-Za-z0-9_!@#$%^&*+./:=?-]*',tail):
            token=token.rstrip('.,:')
            if len(token)<4:
                continue
            # Avoid treating variable names/URLs/account names as exposed secrets.
            if token.startswith(('http','lab_','sample_','demo_')) or token.upper() in ('REDACTED','HIDDEN','PASSWORD','LOGIN','DB_USER'):
                continue
            if token.isdigit():
                if len(token) in (4,6,8):
                    strong.add('credentials')
            elif any(c.isdigit() for c in token) and any(c.isalpha() for c in token) and len(token)>=6:
                strong.add('credentials')
            elif re.fullmatch(r'[a-z]{12,}',token) and re.search(r'[=:—]|впиши|введи|установлен|равен',tail[:tail.find(token)],re.I):
                strong.add('credentials')
            elif re.fullmatch(r'\d{4}(?:[- ]\d{4}){1,3}',token):
                strong.add('credentials')
        if re.search(r'["«][A-Za-zА-Яа-яЁё]+(?:\s+[A-Za-zА-Яа-яЁё]+){1,5}["»]',tail):
            strong.add('credentials')
    if re.search(r'\b\w+://[^\s/:]+:[^\s/@]+@[^\s]+',text):
        strong.add('credentials')
    return {'strong': sorted(strong), 'weak': sorted(weak)}


def rule_predict(text):
    return value_evidence(text)['strong']


def hybrid_predict(model,text):
    from .ml_baseline import scores
    evidence=value_evidence(text)
    values=scores(model,text)
    labels=set(evidence['strong'])
    for label in evidence['weak']:
        if values[label]>=model['models'][label]['threshold']:
            labels.add(label)
    return sorted(labels)
