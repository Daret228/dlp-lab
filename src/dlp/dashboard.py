"""Loopback dashboard over a bounded projection of user journald."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, parse_qs
from .service import UNITS
from .policy_store import PolicyStore, Conflict
from .policy import PolicyError
from .dashboard_control import MonitorControl, ControlError

ASSETS=Path(__file__).with_name('dashboard_assets')
MAX_OUTPUT=8*1024*1024
EVENTS={'policy_loaded','analysis','draft_analysis','file_access_attempt','notification_delivery',
        'local_draft_analysis','local_draft_analysis_error','local_check_finished',
        'text_monitor_started','text_monitor_stopped','monitor_started','queue_overflow','filesystem_coverage',
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


def hex_id(value,length):
    return value if isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) else None


def attach_policy_versions(modules,events,disk_version):
    for module in modules:
        version=None
        if module['active'] in ('active','activating') and module.get('invocation'):
            version=next((e['policy_version'] for e in events
                          if e['event']=='policy_loaded' and e.get('unit')==module['unit']
                          and e.get('invocation')==module['invocation'] and e.get('policy_version')),None)
        module['policy_version']=version
        module['policy_matches_disk']=(version==disk_version) if version and disk_version else None


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
    ml = metadata.get('ml')
    if not isinstance(ml, dict): ml = {}
    result={
        'invocation':hex_id(entry.get('_SYSTEMD_INVOCATION_ID'),32),
        'policy_version':hex_id(e.get('policy_version'),64),
        'ml_complete': ml.get('complete') if type(ml.get('complete')) is bool else None,
        'ml_model_sha256': hex_id(ml.get('model_sha256'),64),
        'ml_categories': [label for label in ('financial','passport','credentials')
                          if isinstance(ml.get('categories'),list) and label in ml['categories']],
        'timestamp':short(e.get('timestamp'),40), 'event':e['event'],
        'unit':short(entry.get('_SYSTEMD_USER_UNIT'),80),
        'decision':r.get('decision',e.get('decision')),
        'categories':categories, 'enforcement':short(e.get('enforcement'),24),
        'complete':r.get('complete',e.get('complete')),
        'reason':short(r.get('reason',e.get('reason')),80),
        'status':short(e.get('status'),40),
        'source':short(e.get('source',e.get('messenger')),60),
        'file_type':short(metadata.get('file_type'),16),
        'scope':short(e.get('scope',metadata.get('scope')),60),
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
                             '-p','Id','-p','ActiveState','-p','SubState','-p','Result','-p','InvocationID'])
                for block in raw.strip().split('\n\n'):
                    fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
                    if fields.get('Id') in UNITS.values():
                        result['modules'].append({'invocation':hex_id(fields.get('InvocationID'),32),'unit':fields['Id'],'active':fields.get('ActiveState','unknown'),
                                                  'sub':fields.get('SubState','unknown'),'result':fields.get('Result','unknown')})
            except (OSError,ValueError,subprocess.TimeoutExpired):
                result['errors'].append('Состояние модулей недоступно.')
            try:disk_version=PolicyStore().get()['version']
            except (OSError,ValueError):disk_version=None
            attach_policy_versions(result['modules'],result['events'],disk_version)
            self.cache[days]=(now,result)
            return result


class DashboardServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,port=8765,source=None):
        self.token=secrets.token_urlsafe(32)
        self.source=source or JournalSource()
        self.policy_store=PolicyStore()
        self.control=MonitorControl(self.policy_store)
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
        if url.path not in ('/api/snapshot','/api/policy'):return self.respond(404,{'error':'not_found'})
        supplied=self.headers.get('Authorization','')
        if not secrets.compare_digest(supplied.encode('utf-8'),('Bearer '+self.server.token).encode('utf-8')):
            return self.respond(401,{'error':'unauthorized'})
        if url.path=='/api/policy':
            if url.query:return self.respond(400,{'error':'invalid_query'})
            try:return self.respond(200,self.server.policy_store.get())
            except (OSError,ValueError):return self.respond(503,{'error':'policy_unavailable'})
        query=parse_qs(url.query)
        if set(query)-{'days'} or len(query.get('days',['7']))!=1:return self.respond(400,{'error':'invalid_query'})
        value=query.get('days',['7'])[0]
        if value not in ('1','7','30'):return self.respond(400,{'error':'invalid_days'})
        return self.respond(200,self.server.source.snapshot(int(value)))

    def do_POST(self):
        if self.path not in ('/api/policy','/api/policy/preview','/api/control'):
            return self.respond(404,{'error':'not_found'})
        host=self.headers.get('Host','')
        if host not in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}') or self.headers.get('Origin')!=f'http://{host}':
            return self.respond(403,{'error':'invalid_origin'})
        if not secrets.compare_digest(self.headers.get('Authorization','').encode(),('Bearer '+self.server.token).encode()):
            return self.respond(401,{'error':'unauthorized'})
        try:
            if self.headers.get('Content-Type')!='application/json' or self.headers.get('Transfer-Encoding'):
                raise ValueError()
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or not 0<int(lengths[0])<=8192:raise ValueError()
            self.connection.settimeout(5)
            def pairs(items):
                obj={}
                for key,value in items:
                    if key in obj:raise ValueError()
                    obj[key]=value
                return obj
            def invalid_constant(value):raise ValueError()
            request=json.loads(self.rfile.read(int(lengths[0])),object_pairs_hook=pairs,parse_constant=invalid_constant)
            if self.path=='/api/control':
                result=self.server.control.execute(request)
                with self.server.source.lock:self.server.source.cache.clear()
            else:
                result=self.server.policy_store.update(request,preview=self.path.endswith('/preview'))
            return self.respond(200,result)
        except ControlError as error:return self.respond(409,{'error':'control_failed','message':str(error)})
        except Conflict:return self.respond(409,{'error':'policy_changed'})
        except (ValueError,TypeError,OverflowError):return self.respond(400,{'error':'invalid_policy'})
        except OSError:return self.respond(503,{'error':'policy_write_failed'})


def run(port=8765):
    if not 1024<=port<=65535:raise ValueError('Порт должен быть от 1024 до 65535')
    server=DashboardServer(port)
    print(f'Панель: http://127.0.0.1:{port}/#token={server.token}',flush=True)
    print('События, политика и управление. Ctrl+C останавливает только панель.',flush=True)
    try:server.serve_forever(poll_interval=0.3)
    finally:server.server_close()
