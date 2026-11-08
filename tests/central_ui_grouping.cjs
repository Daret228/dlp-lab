// Minimal DOM harness for the real table renderer; no browser/session data.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(){this.children=[];this.textContent='';this.value='';this.checked=false;}
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
const context={document:{getElementById:get,createElement:()=>new Element()},setInterval:()=>{}};
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
