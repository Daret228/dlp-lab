// Minimal DOM harness for the agent-update section; no browser/session data.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(){this.dataset={};this.children=[];this.textContent='';this.value='';this.checked=false;this.disabled=false;this.hidden=false;this.files=[];}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=nodes;}
  setAttribute(){}
  addEventListener(){}
  querySelectorAll(){return [];}
  close(){}
  showModal(){}
}
class Option {
  constructor(text,value){this.text=text;this.value=value;this.textContent=text;}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const context={document:{getElementById:get,createElement:()=>new Element(),createTextNode:t=>{const n=new Element();n.textContent=t;return n;}},Option,setInterval:()=>{},console};
vm.createContext(context);
const source=fs.readFileSync('src/dlp/central_ui.js','utf8');
vm.runInContext(source,context);
const fresh=new Date().toISOString();
const text=n=>[n.textContent,...n.children.map(text)].join(' ');

// Assignment requires a fresh, management-capable agent that opted into updates.
assert.equal(vm.runInContext(`updatable({last_seen:'${fresh}',health:{timestamp:'${fresh}',management_ready:true,auto_update:true}})`,context),true);
assert.equal(vm.runInContext(`updatable({last_seen:'${fresh}',health:{timestamp:'${fresh}',management_ready:true}})`,context),false);
assert.equal(vm.runInContext(`updatable({last_seen:'${fresh}',health:{timestamp:'2000-01-01T00:00:00Z',management_ready:true,auto_update:true}})`,context),false);
assert.equal(vm.runInContext(`manageable({last_seen:'${fresh}',health:{timestamp:'${fresh}',management_ready:true,auto_update:true}})`,context),true);
console.log('PASS: update assignment requires fresh agent with auto_update capability');

// Upload validation happens client-side before any network request.
assert.match(vm.runInContext(`updateFileError(undefined)`,context),/Выберите файл/);
assert.match(vm.runInContext(`updateFileError({name:'evil.deb',size:10})`,context),/Имя файла/);
assert.match(vm.runInContext(`updateFileError({name:'dlp-lab_1.0_amd64.deb.exe',size:10})`,context),/Имя файла/);
assert.match(vm.runInContext(`updateFileError({name:'dlp-lab_1.0_amd64.deb',size:4194305})`,context),/4 МиБ/);
assert.equal(vm.runInContext(`updateFileError({name:'dlp-lab_0.2.37~deb12u1_amd64.deb',size:264000})`,context),'');
console.log('PASS: package file is checked by name and size before upload');

vm.runInContext(`
data={agents:[
  {id:'a',name:'main',last_seen:'${fresh}',health:{timestamp:'${fresh}',management_ready:true,auto_update:true,policy_version:'0'}},
  {id:'b',name:'legacy',last_seen:'${fresh}',health:{timestamp:'${fresh}',management_ready:true}}],
 updates:{uploads:[{sha256:'${'a'.repeat(64)}',version:'0.2.37',filename:'dlp-lab_0.2.37_amd64.deb',size:275000,created:'2026-11-17T10:00:00Z'}],
          assignments:{a:{sha256:'${'a'.repeat(64)}'}}}};
renderUpdates();
`,context);
// Only the update-capable device is offered; the legacy agent is filtered out.
const pick=get('update-agent');
assert.equal(pick.children.length,2);
assert.equal(pick.children[1].value,'a');
const list=get('update-list');
assert.equal(list.children.length,1);
assert.match(text(list.children[0]),/dlp-lab_0\.2\.37_amd64\.deb/);
assert.match(text(list.children[0]),/Назначено: main/);
assert.equal(list.children[0].children[2].disabled,true);
console.log('PASS: uploaded package lists with assignment and gated device choice');

vm.runInContext(`$('update-agent').value='a';renderUpdates();`,context);
assert.equal(get('update-list').children[0].children[2].disabled,false);
vm.runInContext(`data.updates={uploads:[],assignments:{}};renderUpdates();`,context);
assert.match(text(get('update-list')),/Пакеты ещё не загружены/);
console.log('PASS: assign button follows device selection; empty state explains itself');
