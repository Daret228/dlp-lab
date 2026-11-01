const statusBox = document.getElementById('status');
const labels = {name:'Устройство',id:'ID',last_seen:'Последняя связь',agent:'Устройство',received:'Получено',event:'Событие',decision:'Решение',enforcement:'Применение',decisions:'Итоги проверки',kind:'Задание',created:'Создано',status:'Состояние',result:'Результат'};
const states = {pending:'Ожидает агента',completed:'Выполнено',failed:'Ошибка выполнения',expired:'Истёк срок ожидания'};
async function api(path, body) {
  const options = {headers:{Authorization:'Bearer '+document.getElementById('token').value},cache:'no-store'};
  if (body !== undefined) { options.method='POST'; options.headers['Content-Type']='application/json'; options.body=JSON.stringify(body); }
  const r=await fetch(path,options);
  if (!r.ok) throw Error(r.status===401?'Нет доступа: проверьте токен':r.status===400?'Задание не принято: возможно, уже есть ожидающий запрос':'Сервер недоступен');
  return r.json();
}
function table(target, rows, columns, devices, commands) {
  const t=document.createElement('table');
  const head=document.createElement('tr');
  for (const c of columns) { const th=document.createElement('th'); th.textContent=labels[c]; head.append(th); }
  if (target==='agents') { const th=document.createElement('th'); th.textContent='Управление'; head.append(th); }
  t.append(head);
  for (const row of rows) {
    const tr=document.createElement('tr');
    for (const c of columns) {
      const td=document.createElement('td');
      let value=row[c];
      if (c==='agent') value=devices.get(value)||value;
      if (c==='status') value=states[value]||value;
      if (c==='kind' && value==='diagnose') value='Диагностика';
      if (c==='created') value=new Date(value*1000).toLocaleString();
      if (c==='result' && value) value=value.checks.map(x=>x.name+': '+x.status).join('\n') || 'Проверка не выполнена';
      td.textContent=value==null?'—':typeof value==='object'?JSON.stringify(value):value;
      td.style.whiteSpace='pre-line'; tr.append(td);
    }
    if (target==='agents') {
      const td=document.createElement('td'), button=document.createElement('button');
      button.textContent='Запросить диагностику';
      button.disabled=commands.some(c=>c.agent===row.id && c.status==='pending');
      button.onclick=async()=>{
        button.disabled=true;
        try { await api('/api/commands',{agent:row.id,kind:'diagnose'}); await refresh(); statusBox.textContent='Запрос принят. Обновите через 30 секунд; ожидание — до 15 минут.'; }
        catch(e) {statusBox.textContent=e.message; button.disabled=false;}
      };
      td.append(button); tr.append(td);
    }
    t.append(tr);
  }
  document.getElementById(target).replaceChildren(t);
}
async function refresh() {
  try {
    const d=await api('/api/report'), devices=new Map(d.agents.map(a=>[a.id,a.name]));
    table('agents',d.agents,['name','id','last_seen'],devices,d.commands||[]);
    table('commands',d.commands||[],['agent','kind','created','status','result'],devices,[]);
    table('events',d.events,['agent','received','event','decision','enforcement','decisions'],devices,[]);
    statusBox.textContent='Обновлено';
  } catch(e) {statusBox.textContent=e.message;}
}
document.getElementById('refresh').onclick=refresh;
