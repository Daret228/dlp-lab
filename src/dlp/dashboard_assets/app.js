'use strict';
const $=id=>document.getElementById(id);
const suppliedToken=new URLSearchParams(location.hash.slice(1)).get('token');
if(suppliedToken)sessionStorage.setItem('dlp-session-token',suppliedToken);
const token=suppliedToken||sessionStorage.getItem('dlp-session-token');
history.replaceState(null,'',location.pathname);
let snapshot=null,busy=false;
const names={file_access_attempt:'Открытие файла',draft_analysis:'Текст в Telegram',local_draft_analysis:'Локальный черновик',notification_delivery:'Уведомление',text_monitor_started:'Наблюдение запущено',text_monitor_stopped:'Наблюдение завершено',monitor_started:'Файловый монитор запущен',local_check_finished:'Проверка хранилища',local_locations_inspection:'Метаданные хранилища',analysis:'Анализ',notification_test_analysis:'Тест уведомления',queue_overflow:'Потеря покрытия',export_message_analysis:'Текст из экспорта',export_analysis_summary:'Итог экспорта'};
const categories={financial:'Финансовые',passport:'Паспортные',credentials:'Данные доступа',confidential:'Конфиденциальные',personal:'Персональные',internal:'Внутренние'};
const units={'dlp-lab-files.service':'Файлы','dlp-lab-text.service':'Поле ввода','dlp-lab-export.service':'Экспорт','dlp-lab-local.service':'Хранилище','dlp-lab-notification-test.service':'Тест уведомлений'};
const sources={atspi_draft:'Поле ввода',telegram:'Telegram',telegram_local_tdata_copy:'Данные на диске',telegram_local_draft:'Локальный черновик',file_sensitive_advisory:'Проверка файла',synthetic_notification_test:'Тестовое предупреждение'};
const reasons={interrupted:'Остановлено',duration_elapsed:'Время теста истекло',process_out_of_scope:'Вне области контроля',sensitive_alerts_incomplete:'Новые категории проверены не полностью',requires_exactly_one_marked_draft:'Тестовый черновик не определён'};
const delivery={accepted:'Принято службой',queued:'В очереди',suppressed_rate_limit:'Повтор подавлен',failed:'Ошибка доставки',unavailable:'Служба недоступна',timeout:'Тайм-аут',queue_full:'Очередь заполнена'};
function el(tag,text,cls){const node=document.createElement(tag);node.textContent=text??'—';if(cls)node.className=cls;return node;}
function render(){if(!snapshot)return;
 const rows=snapshot.events.filter(e=>(!$('category').value||e.categories.includes($('category').value))&&(!$('decision').value||e.decision===$('decision').value)&&(!$('source').value||e.event===$('source').value));
 $('count').textContent=rows.length;$('warn').textContent=rows.filter(e=>e.decision==='WARN'&&e.event!=='notification_delivery').length;$('block').textContent=rows.filter(e=>e.decision==='BLOCK'&&e.event!=='notification_delivery').length;$('deny').textContent=rows.filter(e=>e.enforcement==='DENY').length;
 $('rows').replaceChildren();for(const e of rows){const tr=document.createElement('tr');const date=new Date(e.timestamp);tr.append(el('td',Number.isNaN(date.valueOf())?'Время неизвестно':date.toLocaleString('ru-RU')));const type=el('td',names[e.event]||e.event);type.append(el('small',sources[e.source]||e.source||units[e.unit]||'Агент'));tr.append(type,el('td',e.categories.map(x=>categories[x]||x).join(', ')||'—','categories'));const decision=el('td','');decision.append(el('span',e.decision||'—','badge '+(e.decision||'')));tr.append(decision);tr.append(el('td',delivery[e.status]||e.status||({observe_only:'Наблюдение',ALLOW:'Открытие разрешено',DENY:'Открытие запрещено',none:'Без запрета'}[e.enforcement])||'—'));const complete=el('td',e.complete===true?'Завершена':e.complete===false?'Неполная':'—');if(e.reason)complete.append(el('small',reasons[e.reason]||e.reason));if(e.file_type)complete.append(el('small',(e.scope==='docx_word_text_parts'||e.scope==='pdf_extracted_text_only'?'Текст ':'')+e.file_type.toUpperCase()));tr.append(complete);$('rows').append(tr);}
 $('empty').hidden=rows.length>0;$('shown').textContent=`Показано ${rows.length} из ${snapshot.events.length} событий`;
 $('updated').textContent='Обновлено '+new Date(snapshot.updated_at).toLocaleTimeString('ru-RU')+' · время событий местное';
 $('modules').replaceChildren();for(const m of snapshot.modules){const state={active:'процесс запущен',inactive:'остановлен',failed:'ошибка',activating:'запуск',deactivating:'остановка'}[m.active]||'неизвестно';$('modules').append(el('div',`${units[m.unit]||m.unit}: ${state}`,'module '+(m.active==='active'?'running':m.active==='failed'?'failed':'')));}
 const messages=[...snapshot.errors];if(snapshot.sample_limited)messages.push('Достигнут лимит 1000 записей. Сводка показывает только загруженную часть журнала.');$('notice').textContent=messages.join(' ');$('notice').hidden=!messages.length;
}
async function refresh(){if(busy)return;if(!token){$('notice').hidden=false;$('notice').textContent='Откройте полную ссылку из терминала запуска панели: в ней есть ключ доступа к этой сессии.';$('updated').textContent='Нет доступа к журналу';return;}
 busy=true;$('refresh').disabled=true;
 try{const response=await fetch('/api/snapshot?days='+encodeURIComponent($('days').value),{headers:{Authorization:'Bearer '+token}});if(!response.ok)throw new Error(response.status===401?'Ключ доступа устарел. Откройте ссылку текущего запуска панели.':'Не удалось получить данные панели.');snapshot=await response.json();render();}
 catch(error){$('notice').textContent=error.message;$('notice').hidden=false;$('updated').textContent='Обновление не удалось; ранее загруженные данные могут быть устаревшими.';}
 finally{busy=false;$('refresh').disabled=false;}
}
$('refresh').addEventListener('click',refresh);$('days').addEventListener('change',refresh);for(const key of ['category','decision','source'])$(key).addEventListener('change',render);refresh();setInterval(refresh,10000);
