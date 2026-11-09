// Minimal DOM harness for the real table renderer; no browser/session data.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(){this.dataset={};this.children=[];this.textContent='';this.value='';this.checked=false;}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=nodes;}
  setAttribute(){}
  addEventListener(){}
  querySelectorAll(){return [];}
  close(){}
  showModal(){}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const context={document:{getElementById:get,createElement:()=>new Element(),createTextNode:t=>{const n=new Element();n.textContent=t;return n;}},setInterval:()=>{}};
vm.createContext(context);
const source=fs.readFileSync('src/dlp/central_ui.js','utf8');
vm.runInContext(source+`
const sample={agent:'a',event:'file_access_attempt',decision:'BLOCK',enforcement:'DENY',received:'2026-11-05T12:00:00Z',attempts_in_view:3};
data={agents:[{id:'a',name:'test'}],events:[sample,sample,sample],event_groups:[sample],commands:[]};
renderEvents();
`,context);
assert.equal(get('event-count').textContent,'Строк: 1 · 3 исходных событий в выборке');
const text=n=>[n.textContent,...n.children.map(text)].join(' ');
assert.match(text(get('events')),/Попыток открытия: 3/);
assert.equal(get('events').children[0].children[1].children.length,1);
console.log('PASS: actual UI renders three attempts as one row');
const healthText=vm.runInContext(`healthDescription({last_seen:new Date().toISOString(),health:{timestamp:new Date().toISOString(),session_state:'stopped',files_state:'active'}})`,context);
assert.match(healthText,/Текст: остановлен/);
const stale=vm.runInContext(`healthDescription({last_seen:new Date().toISOString(),health:{timestamp:'2000-01-01T00:00:00Z',session_state:'ready',files_state:'active'}})`,context);
assert.match(stale,/нет свежих данных/);
console.log('PASS: stopped and stale control are not displayed as healthy');

assert.equal(vm.runInContext(`manageable({last_seen:new Date().toISOString(),health:{timestamp:new Date().toISOString(),management_ready:true}})`,context),true);
assert.equal(vm.runInContext(`manageable({last_seen:new Date().toISOString(),health:{timestamp:'2000-01-01T00:00:00Z',management_ready:true}})`,context),false);
assert.equal(vm.runInContext(`manageable({last_seen:new Date().toISOString(),health:{timestamp:new Date().toISOString()}})`,context),false);
console.log('PASS: restart requires fresh management capability');

vm.runInContext(`data.events=[{agent:'a',event:'file_operation',decision:'ALLOW',enforcement:'ALLOW',operation_count:8,received:new Date().toISOString()}];data.event_groups=data.events;renderEvents();`,context);
assert.match(text(get('events')),/Операция с файлом/);
assert.doesNotMatch(text(get('events')),/Попыток открытия/);
console.log('PASS: one final file operation without intermediate opens');
vm.runInContext(`data.events=[{agent:'a',event:'file_operation',file_path:'/home/test/<report>.txt',decision:'WARN',enforcement:'ALLOW',analyzers:['ml'],categories:['credentials'],received:new Date().toISOString()}];data.event_groups=data.events;renderEvents();`,context);
assert.match(text(get('events')),/<report>\.txt/);
assert.match(text(get('events')),/Предположение ML-модели/);
assert.equal(get('events').children[0].children[1].children.length,1);
console.log('PASS: file and cause appear as text in a single operation');
vm.runInContext(`
const fixture=[
 {event:'file_operation',file_path:'/home/test/public.txt',decision:'ALLOW'},
 {event:'file_operation',file_path:'/home/test/.bashrc',decision:'ALLOW'},
 {event:'file_operation',file_path:'/home/test/.local/share/recently-used.xbel.ABC123',decision:'ALLOW'},
 {event:'file_operation',file_path:'/var/lib/dbus/machine-id',decision:'WARN'},
 {event:'file_operation',file_path:'/home/test/secret.txt',decision:'BLOCK',enforcement:'DENY'},
 {event:'notification_delivery',decision:'BLOCK'},
 {event:'monitor_started'}, {event:'endpoint_health'},
 {event:'draft_analysis',decision:'WARN'}, {event:'text_monitor_stopped'},
 {event:'file_operation',decision:'ALLOW'},
 {event:'file_operation',file_path:'/home/test/project/.profile',decision:'ALLOW'},
 {event:'file_operation',file_path:'/home/test/.config/customer.txt',decision:'ALLOW'},
 {event:'file_operation',file_path:'/home/test/.profile',decision:'ALLOW',enforcement:'DENY'}
].map(e=>({...e,agent:'a',messenger:'telegram',received:new Date().toISOString()}));
data.events=fixture;data.event_groups=fixture;
`,context);
const ids=kind=>vm.runInContext(`data.events.map((e,i)=>eventMatches(e,${JSON.stringify(kind)})?i:-1).filter(i=>i>=0).join(',')`,context);
assert.equal(ids('overview'),'0,3,4,8,9,10,11,12,13');
assert.equal(ids('files'),'0,1,2,3,4,10,11,12,13');
assert.equal(ids('technical'),'1,2,3,6,7,9,13');
assert.equal(ids('text'),'8');assert.equal(ids('notifications'),'5');
assert.equal(ids('all'),'0,1,2,3,4,5,6,7,8,9,10,11,12,13');
get('event-filter').value='technical';get('decision-filter').value='WARN';
vm.runInContext('renderEvents()',context);
assert.match(text(get('events')),/machine-id/);
assert.equal(get('events').children[0].children[1].children.length,1);
get('search').value='not-present';vm.runInContext('renderEvents()',context);
assert.match(text(get('events')),/По этим фильтрам событий нет/);
get('reset').onclick();
assert.equal(get('event-filter').value,'overview');assert.equal(get('search').value,'');
assert.equal(get('decision-filter').value,'');
assert.match(get('filter-summary').textContent,/Показано 9 из 14/);
console.log('PASS: event views, retained warnings/denials, exact service paths, combined filters and reset');

// Policy section: badges compare the assigned version with the installed one.
const assigned='a'.repeat(64), disk='b'.repeat(64), stamp=new Date().toISOString();
const badgeText=a=>vm.runInContext(`policyBadge(${JSON.stringify(a)})`,context).textContent;
vm.runInContext(`data.agents=[{id:'dev',name:'test'}];data.policies={};`,context);
assert.match(badgeText({id:'dev'}),/Политика не назначена/);
vm.runInContext(`data.policies={dev:{version:'${assigned}',updated:'${stamp}'}};`,context);
assert.match(badgeText({id:'dev',last_seen:stamp,health:{timestamp:stamp,management_ready:true,policy_version:assigned}}),/Версия на диске совпадает · aaaaaaaa/);
assert.match(badgeText({id:'dev',last_seen:stamp,health:{timestamp:stamp,management_ready:true,policy_version:disk}}),/На устройстве другая политика · назначена aaaaaaaa/);
assert.match(badgeText({id:'dev'}),/Политика назначена · aaaaaaaa/);
console.log('PASS: policy badge distinguishes none, applied, diverged and unknown');
get('policy-agent').value='dev';
vm.runInContext(`data.agents=[{id:'dev',name:'test',last_seen:'${stamp}',health:{timestamp:'${stamp}',management_ready:true,policy_version:'${assigned}'}}];renderPolicy();`,context);
assert.equal(get('policy-state').textContent,'Совпадает на диске');
assert.match(get('policy-status').textContent,/совпадает с политикой на устройстве/);
vm.runInContext(`data.agents=[{id:'dev',name:'test',last_seen:'${stamp}',health:{timestamp:'${stamp}',management_ready:true,policy_version:'${disk}'}}];renderPolicy();`,context);
assert.equal(get('policy-state').textContent,'Расходится');
assert.match(get('policy-status').textContent,/выполните применение/);
vm.runInContext(`data.agents=[{id:'dev',name:'test'}];renderPolicy();`,context);
assert.equal(get('policy-state').textContent,'Назначена');
get('policy-agent').value='';
vm.runInContext('renderPolicy()',context);
assert.equal(get('policy-state').textContent,'');
assert.equal(get('policy-save').disabled,true);
console.log('PASS: policy status explains convergence and save stays disabled without content');
vm.runInContext(`data.commands=[{agent:'dev',kind:'apply_policy',status:'completed',created:Date.now()/1000}];renderCommands();`,context);
assert.match(text(get('commands')),/Применение политики/);
console.log('PASS: apply command is listed with a human name');

assert.doesNotMatch(badgeText({id:'dev',health:{timestamp:'2000-01-01T00:00:00Z',policy_version:assigned}}),/совпадает/);
(async()=>{
 vm.runInContext(`let pendingPolicy={};api=(path)=>new Promise(resolve=>pendingPolicy[path]=resolve);`,context);
 get('policy-agent').value='first';const first=vm.runInContext('loadPolicy()',context);
 get('policy-agent').value='second';const second=vm.runInContext('loadPolicy()',context);
 vm.runInContext(`pendingPolicy['/api/policy?agent=second']({content:'second contents',version:'b'.repeat(64)});`,context);
 await second;
 vm.runInContext(`pendingPolicy['/api/policy?agent=first']({content:'first contents',version:'a'.repeat(64)});`,context);
 await first;
 assert.equal(get('policy-content').value,'second contents');
 vm.runInContext(`let postedPolicy;data.policies={second:{version:'c'.repeat(64)}};api=async(path,body)=>{postedPolicy=body;return {version:'d'.repeat(64)};};refresh=async()=>{};`,context);
 await vm.runInContext('savePolicy(false)',context);
 assert.equal(vm.runInContext('postedPolicy.expected_version',context),'b'.repeat(64));
 console.log('PASS: late policy response cannot overwrite another device; edits keep loaded revision');
})().catch(error=>{console.error(error);process.exitCode=1;});
assert.match(text(vm.runInContext("policyLine({id:'unassigned'})",context)),/Политика не назначена/);
