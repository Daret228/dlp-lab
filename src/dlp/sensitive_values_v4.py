"""Offline v4: bounded value binding and placeholder handling.

V3 is retained unchanged to reproduce its frozen experiment. These heuristics
still do not validate identifiers or passwords against any external authority.
"""
import re
from . import sensitive_values as v3

MASK = re.compile(r'^(?:\*+|_+|\[[^]]*\]|<[^>]*>|\$\{[^}]*\}|REDACTED|HIDDEN|REMOVED)$', re.I)
ABSENT = re.compile(r'не\s+(?:указан\w*|переда\w*|сохран\w*|задан\w*|привед\w*)|отсутств\w*|скрыт\w*|удал[её]н\w*|пуст\w*|not\s+(?:provided|included)|is\s+empty', re.I)
ASSIGN = re.compile(r'[:=—]|\s-\s|\b(?:равен|равна|впиши|введи|установлен\w*(?:\s+в)?|назначена|записан\s+как)\s+', re.I)
NOT_VALUE = {'не','нет','отсутствует','удалён','удален','скрыт','пусто','none','null','empty','redacted','hidden','removed','true','false'}


def candidate(tail):
    tail=tail.lstrip(' \t:=-—')
    if not tail:
        return None
    match=re.match(r'"([^"\n]+)"|«([^»\n]+)»|\x27([^\x27\n]+)\x27|([^\s;,]+)',tail)
    if not match:
        return None
    value=next(g for g in match.groups() if g is not None).rstrip('.,')
    if MASK.fullmatch(value) or value.casefold() in NOT_VALUE:
        return None
    return value


def credential_value(text):
    # Only inspect the clause containing the cue, not unrelated later clauses.
    for clause in re.split(r'[;\n]|(?<=[.!?])\s+',text):
        for m in v3.SECRET.finditer(clause):
            tail=clause[m.end():m.end()+110]
            assignment=ASSIGN.search(tail)
            if assignment:
                prefix=tail[:assignment.start()]
                if ABSENT.search(prefix) or re.search(r'должен|не менее|минимум|длин[аы]|символ',prefix,re.I):
                    continue
                value=candidate(tail[assignment.end():])
                if value is not None:
                    # A request to use a placeholder is not a credential value.
                    if value.casefold() in {'из','from','через','в','the','поле','настройках','хранилища'}:
                        continue
                    return True
            if ABSENT.search(tail):
                continue
            # Without an assignment, accept only an immediately supplied value,
            # or a high-specificity mixed token after short contextual wording.
            value=candidate(tail)
            if value and (re.fullmatch(r'\d{4,12}(?:[- ]\d{4})*',value)
                          or re.fullmatch(r'[A-Za-z0-9_!@#$%^&*+.-]{6,}',value)
                          and re.search(r'[A-Za-z]',value) and re.search(r'\d',value)):
                return True
            if re.search(r'код|code',m[0],re.I) and re.search(r'\b\d{6,8}\b',tail):
                return True
            for token in re.findall(r'\b[A-Za-z][A-Za-z0-9_!@#$%^&*+.-]{5,}',tail):
                if re.search(r'\d',token) and re.search(r'[!@#$%^&*]',token):
                    return True
    return bool(re.search(r'\b\w+://[^\s/:]+:[^\s/@]+@[^\s]+',text))


def value_evidence(text):
    text=v3.normalized(text)
    evidence=v3.value_evidence(text)
    strong=set(evidence['strong'])-{'credentials','passport'}
    if credential_value(text):
        strong.add('credentials')
    # Passport digits must occur in the same clause as the passport cue. An
    # unrelated telephone/order field interrupts binding to the document.
    for clause in re.split(r'[;\n]|(?<=[.!?])\s+',text):
        for m in v3.PASSPORT.finditer(clause):
            window=clause[m.start():m.end()+180]
            window=re.split(r'телефон\w*|заказ\w*|инвентар\w*|станк\w*|прибор\w*',window,flags=re.I)[0]
            if v3.number_windows(window,v3.PASSPORT,[(10,),(4,6),(2,2,6),(9,),(2,7)]):
                strong.add('passport')
    # Structured passport forms can put the series and number on separate lines.
    if v3.PASSPORT.search(text) and re.search(r'сери[яи]|series|serial',text,re.I) and re.search(r'номер|number',text,re.I):
        if v3.number_windows(text,v3.PASSPORT,[(4,6),(2,2,6),(2,7)]):
            strong.add('passport')
    return {'strong':sorted(strong),'weak':evidence['weak']}


def rule_predict(text):
    return value_evidence(text)['strong']


def hybrid_predict(model,text):
    from .ml_baseline import scores
    evidence=value_evidence(text); values=scores(model,text)
    result=set(evidence['strong'])
    for label in evidence['weak']:
        if values[label]>=model['models'][label]['threshold']:
            result.add(label)
    return sorted(result)
