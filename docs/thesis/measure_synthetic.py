import json, platform, statistics, time, hashlib
from pathlib import Path
from dlp.analysis import ContentAnalyzer
from dlp.models import TextContent
from dlp.policy import load_policy
analyzer=ContentAnalyzer(load_policy('config/policy.yaml'))
cases=[('P01','Привет, встречаемся завтра','ALLOW'),('P02','Почта: test@example.com','WARN'),('P03','Это коммерческая тайна','BLOCK'),('P04','КОММЕРЧЕСКАЯ ТАЙНА','BLOCK'),('P05','top secret','BLOCK'),('P06','TOP SECRET','BLOCK'),('P07','Закрытый проект','BLOCK'),('P08','restricted project','BLOCK'),('P09','Проект готов','ALLOW'),('P10','Открытый проект','ALLOW'),('P11','test@example.com test@example.com','WARN'),('P12','коммерческая тайна test@example.com','BLOCK'),('P13','','ALLOW'),('P14','коммерческая тайна коммерческая тайна','BLOCK'),('P15','проект '+('а'*100)+' закрытый','ALLOW'),('P16','проект закрытый','BLOCK')]
probes=[('S01','Это не коммерческая тайна','semantic_negation'),('S02','коммерческую тайну','inflection'),('S03','коммерческая\nтайна','whitespace'),('S04','коммерческая\u00a0тайна','nbsp'),('S05','коммерческая тaйна','mixed_alphabet'),('S06','коммерческая\u200b тайна','zero_width'),('S07','контакт: тест@пример.рф','unicode_email'),('S08','Расписание закрытых встреч по проекту','inflection_context')]
records=[]
for id,t,expected in cases:
 r=analyzer.analyze(TextContent(t)); records.append(dict(id=id,text=t,expected=expected,actual=str(r.decision),score=r.score,complete=r.complete))
probe_records=[]
for id,t,kind in probes:
 r=analyzer.analyze(TextContent(t));probe_records.append(dict(id=id,text=t,probe=kind,actual=str(r.decision),score=r.score,complete=r.complete))
lat=[]
for size in [1024,65536,1048576]:
 text=('ordinary public text '*((size//21)+1))[:size]
 for _ in range(5):analyzer.analyze(TextContent(text))
 samples=[]
 for _ in range(31):
  start=time.perf_counter_ns();r=analyzer.analyze(TextContent(text));samples.append((time.perf_counter_ns()-start)/1e6)
 assert r.complete and r.decision=='ALLOW'
 lat.append(dict(bytes=len(text.encode()),runs=31,warmups=5,min_ms=min(samples),median_ms=statistics.median(samples),max_ms=max(samples),samples_ms=samples))
out=dict(date='2026-10-06',python=platform.python_version(),scope='in_process_TextContent_synthetic_only',policy_sha256=hashlib.sha256(Path('config/policy.yaml').read_bytes()).hexdigest(),functional_cases=records,semantic_probes=probe_records,timing=lat)
Path('docs/research/thesis_synthetic_experiment_2026-10-06.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
print(json.dumps({'functional_passed':sum(r['actual']==r['expected'] and r['complete'] for r in records),'functional_total':len(records),'semantic_probes':probe_records,'timing':[{k:v for k,v in x.items() if k!='samples_ms'} for x in lat]},ensure_ascii=False,indent=2))
