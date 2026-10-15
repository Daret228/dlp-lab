"""Read-only loopback dashboard over a bounded projection of user journald."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, parse_qs
from .service import UNITS

ASSETS=Path(__file__).with_name('dashboard_assets')
MAX_OUTPUT=8*1024*1024
EVENTS={'analysis','draft_analysis','file_access_attempt','notification_delivery',
        'local_draft_analysis','local_draft_analysis_error','local_check_finished',
        'text_monitor_started','text_monitor_stopped','monitor_started','queue_overflow',
        'export_message_analysis','export_analysis_summary','local_locations_inspection',
        'notification_test_analysis'}


def command(args):
    # No shell, caller cannot supply journal selectors or command arguments.
    with tempfile.TemporaryFile() as output:
        p=subprocess.run(args,stdout=output,stderr=subprocess.DEVNULL,timeout=5,check=False)
        if p.returncode:raise ValueError('session_unavailable')
        if output.tell()>MAX_OUTPUT:raise ValueError('journal_output_limit')
        output.seek(0)
        return output.read().decode('utf-8',errors='replace')


def short(value,limit=120):
    return value[:limit] if isinstance(value,str) else None


def project(entry):
    """Allowlist projection: never return raw MESSAGE, paths or message text."""
    if not isinstance(entry,dict):return None
    raw=entry.get('MESSAGE')
    if not isinstance(raw,str) or len(raw)>65536:return None
    try:e=json.loads(raw)
    except ValueError:return None
    if not isinstance(e,dict) or e.get('event') not in EVENTS:return None
    r=e.get('result',{})
    if not isinstance(r,dict):r={}
    findings=r.get('findings',[])
    categories=sorted({short(f.get('category'),48) for f in findings[:100]
                       if isinstance(f,dict) and isinstance(f.get('category'),str)}) if isinstance(findings,list) else []
    metadata=r.get('metadata',{})
    if not isinstance(metadata,dict):metadata={}
    result={
        'timestamp':short(e.get('timestamp'),40), 'event':e['event'],
        'unit':short(entry.get('_SYSTEMD_USER_UNIT'),80),
        'decision':r.get('decision',e.get('decision')),
        'categories':categories, 'enforcement':short(e.get('enforcement'),24),
        'complete':r.get('complete',e.get('complete')),
        'reason':short(r.get('reason',e.get('reason')),80),
        'status':short(e.get('status'),40),
        'source':short(e.get('source',e.get('messenger')),60),
        'file_type':short(metadata.get('file_type'),16),
        'scope':short(metadata.get('scope'),60),
        'send_confirmed':e.get('send_confirmed') is True,
        'send_blocked':e.get('send_blocked') is True,
    }
    if result['decision'] not in ('ALLOW','WARN','BLOCK'):result['decision']=None
    if type(result['complete']) is not bool:result['complete']=None
    # A timestamp in the JSON payload may be absent: fall back to journald.
    if not result['timestamp']:
        try:result['timestamp']=datetime.fromtimestamp(int(entry['__REALTIME_TIMESTAMP'])/1e6,timezone.utc).isoformat()
        except (KeyError,ValueError,TypeError,OverflowError):return None
    return result


class JournalSource:
    def __init__(self):
        self.cache={};self.lock=threading.Lock()

    def snapshot(self,days):
        # Serialize requests and cache repeated browser refreshes for 5 seconds.
        with self.lock:
            now=time.monotonic()
            if days in self.cache and now-self.cache[days][0]<5:return self.cache[days][1]
            result={'events':[],'modules':[],'errors':[], 'days':days,'limit':1000,
                    'sample_limited':False,'updated_at':datetime.now(timezone.utc).isoformat()}
            args=['journalctl','--user','--no-pager','-o','json','-n','1000','--since',f'{days} days ago']
            for unit in UNITS.values():args+=['-u',unit]
            try:
                lines=command(args).splitlines(); result['sample_limited']=len(lines)>=1000
                for line in lines:
                    try:event=project(json.loads(line))
                    except (ValueError,TypeError):continue
                    if event:result['events'].append(event)
                result['events'].reverse()
            except (OSError,ValueError,subprocess.TimeoutExpired):
                result['errors'].append('Журнал недоступен. Запустите панель из пользовательского сеанса Linux.')
            try:
                raw=command(['systemctl','--user','show',*UNITS.values(),
                             '-p','Id','-p','ActiveState','-p','SubState','-p','Result'])
                for block in raw.strip().split('\n\n'):
                    fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
                    if fields.get('Id') in UNITS.values():
                        result['modules'].append({'unit':fields['Id'],'active':fields.get('ActiveState','unknown'),
                                                  'sub':fields.get('SubState','unknown'),'result':fields.get('Result','unknown')})
            except (OSError,ValueError,subprocess.TimeoutExpired):
                result['errors'].append('Состояние модулей недоступно.')
            self.cache[days]=(now,result)
            return result


class DashboardServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,port=8765,source=None):
        self.token=secrets.token_urlsafe(32)
        self.source=source or JournalSource()
        super().__init__(('127.0.0.1',port),Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass  # Do not log request headers or auth material.

    def respond(self,code,data,content_type='application/json; charset=utf-8'):
        if not isinstance(data,bytes):data=json.dumps(data,ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers();self.wfile.write(data)

    def do_GET(self):
        port=self.server.server_port
        hosts={f'127.0.0.1:{port}',f'localhost:{port}'}
        host=self.headers.get('Host','')
        if host not in hosts:return self.respond(403,{'error':'invalid_host'})
        origin=self.headers.get('Origin')
        if origin and origin!=f'http://{host}':return self.respond(403,{'error':'invalid_origin'})
        url=urlsplit(self.path)
        assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
        if url.path in assets:
            name,mime=assets[url.path];return self.respond(200,(ASSETS/name).read_bytes(),mime)
        if url.path!='/api/snapshot':return self.respond(404,{'error':'not_found'})
        supplied=self.headers.get('Authorization','')
        if not secrets.compare_digest(supplied.encode('utf-8'),('Bearer '+self.server.token).encode('utf-8')):
            return self.respond(401,{'error':'unauthorized'})
        query=parse_qs(url.query)
        if set(query)-{'days'} or len(query.get('days',['7']))!=1:return self.respond(400,{'error':'invalid_query'})
        value=query.get('days',['7'])[0]
        if value not in ('1','7','30'):return self.respond(400,{'error':'invalid_days'})
        return self.respond(200,self.server.source.snapshot(int(value)))

    def do_POST(self):self.respond(405,{'error':'read_only'})


def run(port=8765):
    if not 1024<=port<=65535:raise ValueError('Порт должен быть от 1024 до 65535')
    server=DashboardServer(port)
    print(f'Панель: http://127.0.0.1:{port}/#token={server.token}',flush=True)
    print('Только просмотр. Ctrl+C останавливает панель; агент управляется отдельно.',flush=True)
    try:server.serve_forever(poll_interval=0.3)
    finally:server.server_close()
