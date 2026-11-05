from pathlib import Path
import json, re, textwrap
from docx import Document
from docx.shared import Mm, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from PIL import Image, ImageDraw, ImageFont
import subprocess
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
ROOT=Path(__file__).resolve().parents[2]
TMP=ROOT/'build/thesis'; TMP.mkdir(parents=True,exist_ok=True)
OUT=ROOT/'output/docx/VKR_DLP_Linux.docx'; OUT.parent.mkdir(parents=True,exist_ok=True)
CONTENT=ROOT/'docs/thesis/chapters'
PAGE_MAP=json.loads((TMP/'page_map.json').read_text()) if (TMP/'page_map.json').exists() else {}
PAGE_COUNT=PAGE_MAP.get('_pages',0)
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf'
def diagram(name, nodes, edges, height=5):
 width=1800; H=int(width*height/8); im=Image.new('RGB',(width,H),'white');draw=ImageDraw.Draw(im);font=ImageFont.truetype(FONT,50)
 def pt(x,y): return (int(x/10*(width-40)+20),int((10-y)/10*(H-40)+20))
 for x,y,w,h,label in nodes:
  draw.rounded_rectangle([pt(x-w/2,y+h/2),pt(x+w/2,y-h/2)],radius=12,outline='black',width=3)
  box=draw.multiline_textbbox((0,0),label,font=font,spacing=7,align='center');cx,cy=pt(x,y)
  draw.multiline_text((cx-(box[2]-box[0])/2,cy-(box[3]-box[1])/2-box[1]),label,font=font,fill='black',spacing=7,align='center')
 for x1,y1,x2,y2 in edges:
  import math
  a=pt(x1,y1);b=pt(x2,y2);draw.line([a,b],fill='black',width=3);angle=math.atan2(b[1]-a[1],b[0]-a[0]);pts=[b,(b[0]-17*math.cos(angle-.45),b[1]-17*math.sin(angle-.45)),(b[0]-17*math.cos(angle+.45),b[1]-17*math.sin(angle+.45))];draw.polygon(pts,fill='black')
 im.save(TMP/f'{name}.png')

diagram('architecture',[(1.7,8.6,2.7,1.2,'Файл\nfanotify'),(5,8.6,2.7,1.2,'Поле ввода\nAT-SPI'),(8.3,8.6,2.7,1.2,'Локальные данные\nTelegram / Signal'),(5,6.3,6.8,1.2,'Нормализация\nFileContent / TextContent'),(5,4.1,6.8,1.2,'Общий анализ и политика\nALLOW / WARN / BLOCK'),(1.7,1.6,2.7,1.3,'Ответ ядру\nALLOW / DENY'),(5,1.6,2.7,1.3,'Уведомление\nobserve_only'),(8.3,1.6,2.7,1.3,'Отчёт\nretrospective')],[(1.7,8,3,6.9),(5,8,5,6.9),(8.3,8,7,6.9),(5,5.7,5,4.7),(3,3.5,1.7,2.25),(5,3.5,5,2.25),(7,3.5,8.3,2.25)],5.4)
diagram('privileges',[(5,8.7,7,1.3,'Системная служба systemd\nФиксированный исполнитель'),(5,6.2,7,1.3,'Привилегированный C-брокер\nМетки файловых систем'),(5,3.7,7,1.3,'Локальный канал\nПередача FD и решения'),(5,1.2,7,1.3,'Python-анализатор\nПолномочия пользователя')],[(5,8.05,5,6.85),(5,5.55,5,4.35),(5,3.05,5,1.85)],5.5)
diagram('fileflow',[(5,9,7,1,'Событие открытия и FD объекта'),(5,7,7,1,'Определение процесса и области'),(5,5,7,1,'Чтение FD и анализ содержимого'),(5,3,7,1,'Решение и ответ ядру'),(5,1,7,1,'Закрытие event FD и запись аудита')],[(5,8.5,5,7.5),(5,6.5,5,5.5),(5,4.5,5,3.5),(5,2.5,5,1.5)],5.6)
diagram('lifecycle',[(5,9,6,1,'Неактивен'),(5,6.8,6,1,'Запуск процесса'),(5,4.5,6,1.3,'Активен\nГотовность подтверждается событием'),(2.4,1.7,4,1.3,'Завершён / остановлен\nРезультат в журнале'),(7.5,1.7,4,1.3,'Ошибка\nДиагностика в журнале')],[(5,8.5,5,7.3),(5,6.3,5,5.15),(3.6,3.85,2.4,2.35),(6.4,3.85,7.5,2.35)],5.5)
pdfmetrics.registerFont(TTFont('DLPSerif',FONT))
drawing=Drawing(520,280);chart=VerticalBarChart();chart.x=60;chart.y=45;chart.width=420;chart.height=205;chart.data=[(.060095,3.364609,59.847923)];chart.categoryAxis.categoryNames=['1 KiB','64 KiB','1 MiB'];chart.valueAxis.valueMin=0;chart.valueAxis.valueMax=70;chart.valueAxis.valueStep=10;chart.categoryAxis.labels.fontName='DLPSerif';chart.valueAxis.labels.fontName='DLPSerif';chart.bars[0].fillColor=colors.lightgrey;chart.bars[0].strokeColor=colors.black;chart.barLabels.fontName='DLPSerif';chart.barLabels.fontSize=14;chart.categoryAxis.labels.fontSize=14;chart.valueAxis.labels.fontSize=14;chart.barLabels.dy=12;chart.barLabelFormat='%.3f';drawing.add(chart);drawing.add(String(8,262,'Медиана, мс',fontName='DLPSerif',fontSize=14));drawing.add(String(210,12,'Размер TextContent',fontName='DLPSerif',fontSize=14));renderPDF.drawToFile(drawing,str(TMP/'timing-chart.pdf'))
subprocess.run(['/home/roman/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/override/pdftoppm','-png','-singlefile','-scale-to','1800',str(TMP/'timing-chart.pdf'),str(TMP/'timing')],check=True)

D=Document(); sec=D.sections[0];sec.page_width=Mm(210);sec.page_height=Mm(297);sec.left_margin=Mm(30);sec.right_margin=Mm(15);sec.top_margin=Mm(20);sec.bottom_margin=Mm(20);sec.footer_distance=Mm(10);sec.different_first_page_header_footer=True
styles=D.styles
for name in ['Normal','Title','Heading 1','Heading 2','Heading 3','Caption','TOC Heading']:
 st=styles[name];st.font.name='Times New Roman';st.font.size=Pt(14);st.font.color.rgb=RGBColor(0,0,0)
 st._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'Times New Roman')
normal=styles['Normal'].paragraph_format;normal.first_line_indent=Mm(12.5);normal.line_spacing=1.5;normal.space_before=Pt(0);normal.space_after=Pt(0);normal.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY;normal.widow_control=True
for name in ['Heading 1','Heading 2']:
 st=styles[name];st.font.bold=True;pf=st.paragraph_format;pf.line_spacing=1.5;pf.keep_with_next=True;pf.space_after=Pt(12);pf.space_before=Pt(12)
styles['Heading 1'].paragraph_format.page_break_before=True;styles['Heading 1'].paragraph_format.first_line_indent=Mm(0);styles['Heading 1'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.CENTER
styles['Heading 2'].paragraph_format.first_line_indent=Mm(12.5);styles['Heading 2'].paragraph_format.alignment=WD_ALIGN_PARAGRAPH.LEFT
styles['Title'].font.size=Pt(14);styles['Title'].font.bold=True;styles['Title'].paragraph_format.line_spacing=1.5
for name,size in [('Code',12),('Table Text',12),('TOC Entry',14),('Small',12)]:
 if name not in styles: styles.add_style(name,1)
 st=styles[name];st.base_style=styles['Normal'];st.font.name='Times New Roman';st.font.size=Pt(size);pf=st.paragraph_format;pf.first_line_indent=Mm(0);pf.space_after=Pt(0)
 if name in ['Code','Table Text','Small']:pf.line_spacing=1.0
 if name=='Code':st.font.name='Liberation Mono';pf.alignment=WD_ALIGN_PARAGRAPH.LEFT;pf.keep_with_next=False
styles['Caption'].font.size=Pt(12);styles['Caption'].paragraph_format.first_line_indent=Mm(0);styles['Caption'].paragraph_format.line_spacing=1;styles['Caption'].paragraph_format.space_after=Pt(8)
# Page number: cover counted but not printed.
f=sec.footer.paragraphs[0];f.alignment=WD_ALIGN_PARAGRAPH.CENTER;f.paragraph_format.first_line_indent=Mm(0)
r=f.add_run();fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');r._r.addnext(fld)
D.core_properties.title='Разработка системы контроля утечек информации в мессенджерах под управлением ОС Linux';D.core_properties.author='';D.core_properties.subject='Выпускная квалификационная работа специалиста';D.core_properties.keywords='Linux, DLP, Telegram, Signal, fanotify, AT-SPI, ML'
settings=D.settings.element; lang=OxmlElement('w:themeFontLang');lang.set(qn('w:val'),'ru-RU');settings.append(lang)
normal_rpr=styles['Normal']._element.get_or_add_rPr();lng=OxmlElement('w:lang');lng.set(qn('w:val'),'ru-RU');normal_rpr.append(lng)
for st in styles:
 if st.type == 1:
  rp=st._element.get_or_add_rPr()
  for rf in rp.findall(qn('w:rFonts')):
   for attr in list(rf.attrib):
    if attr.endswith('Theme'):del rf.attrib[attr]
  for color in rp.findall(qn('w:color')):
   for attr in list(color.attrib):
    if 'theme' in attr:del color.attrib[attr]
  for border in list(st._element.iter(qn('w:pBdr'))):border.getparent().remove(border)
headings=[];table_count=0;figure_count=0

def para(text='',style=None,align=None,indent=None):
 p=D.add_paragraph(text,style);pf=p.paragraph_format
 if align is not None:p.alignment=align
 if indent is not None:pf.first_line_indent=Mm(indent)
 return p

def heading(text,level=1):
 p=para(text,f'Heading {level}');key=f'h{len(headings)}';start=OxmlElement('w:bookmarkStart');start.set(qn('w:id'),str(len(headings)+1));start.set(qn('w:name'),key);end=OxmlElement('w:bookmarkEnd');end.set(qn('w:id'),str(len(headings)+1));p._p.insert(0,start);p._p.append(end);headings.append((text,level,key));return p

def table(label,title,rows,continuation=False):
 global table_count
 if label in ['А.1','Д.1'] and len(rows)>10 and not continuation:
  table(label,title,rows[:9]);table(label,title,[rows[0]]+rows[9:],True);return
 if not continuation:table_count+=1
 caption=f'Продолжение таблицы {label}' if continuation else f'Таблица {label} — {title}'
 cp=para(caption,'Caption',WD_ALIGN_PARAGRAPH.LEFT);cp.paragraph_format.keep_with_next=True
 t=D.add_table(rows=1,cols=len(rows[0]));t.alignment=WD_TABLE_ALIGNMENT.CENTER;t.autofit=False
 widths={2:[48,117],3:[55,55,55],4:[37,43,44,41],5:[25,30,36,37,37]}.get(len(rows[0]),[165/len(rows[0])]*len(rows[0]))
 if len(rows[0])==3 and label not in ['5','9']: widths=[40,55,70]
 if label=='В.2':widths=[50,50,65]
 for c,w in zip(t.columns,widths):c.width=Mm(w)
 for idx,row in enumerate(rows):
  cells=t.rows[0].cells if idx==0 else t.add_row().cells
  trpr=cells[0]._tc.getparent().get_or_add_trPr();ns=OxmlElement('w:cantSplit');trpr.append(ns)
  if idx==0:rep=OxmlElement('w:tblHeader');trpr.append(rep)
  for cell,text,w in zip(cells,row,widths):
   cell.width=Mm(w);cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
   p=cell.paragraphs[0];p.style=styles['Table Text'];p.paragraph_format.keep_with_next=idx<len(rows)-1;p.alignment=WD_ALIGN_PARAGRAPH.LEFT;p.paragraph_format.space_before=Pt(3);p.paragraph_format.space_after=Pt(3);r=p.add_run(text.strip());r.bold=idx==0
   pr=cell._tc.get_or_add_tcPr();m=OxmlElement('w:tcMar')
   for side in ['top','left','bottom','right']:
    e=OxmlElement('w:'+side);e.set(qn('w:w'),'75');e.set(qn('w:type'),'dxa');m.append(e)
   pr.append(m)
   if idx==0:s=OxmlElement('w:shd');s.set(qn('w:fill'),'EEEEEE');pr.append(s)
 borders=OxmlElement('w:tblBorders')
 for side in ['top','left','bottom','right','insideH','insideV']:
  e=OxmlElement('w:'+side);e.set(qn('w:val'),'single');e.set(qn('w:sz'),'5');e.set(qn('w:color'),'D9D9D9');borders.append(e)
 t._tbl.tblPr.append(borders)
 para('').paragraph_format.line_spacing=0.3

def code(text):
 for line in text.splitlines():
  # Wrap long source lines without changing executable source files.
  parts=textwrap.wrap(line,width=66,replace_whitespace=False,drop_whitespace=False) or ['']
  for part in parts:para(part,'Code')
 para('').paragraph_format.line_spacing=.3

# Cover with blank fields requested by the user.
p=para('Министерство науки и высшего образования Российской Федерации',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.line_spacing=1
p=para('[Полное наименование образовательной организации]',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.line_spacing=1;p.paragraph_format.space_after=Pt(24)
for text in ['Институт ______________________________','Кафедра / департамент __________________','Специальность __________________________']:
 p=para(text,indent=0);p.paragraph_format.space_after=Pt(8)
p=para('ВЫПУСКНАЯ КВАЛИФИКАЦИОННАЯ РАБОТА','Title',WD_ALIGN_PARAGRAPH.CENTER,0);p.paragraph_format.space_before=Pt(30)
para('Дипломная работа',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0)
p=para('РАЗРАБОТКА СИСТЕМЫ КОНТРОЛЯ УТЕЧЕК ИНФОРМАЦИИ В МЕССЕНДЖЕРАХ ПОД УПРАВЛЕНИЕМ ОС LINUX',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.space_before=Pt(14);p.paragraph_format.space_after=Pt(25)
for text in ['Руководитель __________________________','Должность, учёная степень, звание __________','Подпись ______________________________','Нормоконтролёр ________________________','Студент ______________________________','Группа __________ Подпись ______________']:
 p=para(text,indent=0);p.paragraph_format.line_spacing=1.2;p.paragraph_format.space_after=Pt(6)
p=para('[Город]',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.space_before=Pt(100);para('[Год защиты]',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0)
heading('ЗАДАНИЕ НА ВЫПОЛНЕНИЕ ВКР')
for text in ['Студент _____________________ Группа __________','Специальность ________________________________','Руководитель _________________________________','Утверждено распоряжением от __________ № _______']:
 para(text,indent=0)
para('Тема: разработка системы контроля утечек информации в мессенджерах под управлением ОС Linux.')
para('Исходные данные: собственный Linux-стенд, открытая техническая документация, искусственные тексты и файлы, согласованные тестовые аккаунты Telegram и Signal, исходный код прототипа DLP Lab.')
para('Содержание работы: анализ угроз и интерфейсов; проектирование модульной системы; реализация анализа и адаптеров; экспериментальная проверка; анализ результатов и рекомендации.')
para('Демонстрационные материалы: схема архитектуры, схема полномочий, файловый алгоритм, состояния модулей, результаты испытаний.')
for text in ['Срок сдачи _________________________________','Плановые сроки этапов: анализ ______; разработка ______; испытания ______; оформление ______.','Руководитель _____________ /________________/','Задание принято __________ /________________/']:
 para(text,indent=0)
heading('РЕФЕРАТ')
abstract_count=para(f'ВКР {PAGE_COUNT or "___"} с., 5 рис., 17 табл., 24 источника, 5 приложений.')
para('LINUX, DLP, TELEGRAM, SIGNAL, FANOTIFY, AT-SPI, МАШИННОЕ ОБУЧЕНИЕ, АУДИТ',indent=0)
para('Объект исследования — обработка информации настольными мессенджерами Linux. Цель — разработка модульной системы контроля файлов, текстовых полей и локальных данных. Реализованы анализ правил и обучаемая модель, файловый контроль fanotify, наблюдение AT-SPI, чтение черновиков Telegram и выборки локальных текстов Signal. Созданы DEB-пакет, системные службы, установщик и центральный журнал с удалённой диагностикой. На двухмашинном стенде проверены контроль файлов, доставка событий и автозапуск. Классификатор финансовых сведений, паспортных данных и данных доступа оценён на диагностическом синтетическом наборе. Результаты представлены в виде журналируемых событий и доступны администратору в веб-панели.')
# TOC filled after all headings have been registered.
p=para('СОДЕРЖАНИЕ','Heading 1');toc_anchor=p
heading('ТЕРМИНЫ И ОПРЕДЕЛЕНИЯ')
for term,definition in [
('Агент','программные компоненты, выполняющие сбор и анализ данных на конечной станции.'),('Адаптер','компонент, получающий данные конкретного источника и приводящий их к общему контракту.'),('Контентный анализ','поиск заданных признаков в доступном текстовом содержимом.'),('Политика','конфигурация правил, весов, порогов и обработки ошибок.'),('Нормализация','преобразование представления источника без приписывания отсутствующих сведений.'),('Permission-событие','запрос решения по ожидающей файловой операции.'),('Наблюдение','получение и проверка данных без обязательного запрета действия приложения.'),('Ретроспективный анализ','проверка уже сформированной истории или экспорта.'),('Fail-open','продолжение доступа после потери механизма контроля в рассматриваемой модели.'),('Покрытие','явно определённый набор источников, объектов и операций, доступных проверке.')]:
 para(f'{term} — {definition}')
heading('ПЕРЕЧЕНЬ СОКРАЩЕНИЙ И ОБОЗНАЧЕНИЙ')
for a,b in [('ВКР','выпускная квалификационная работа'),('ОС','операционная система'),('DLP','Data Loss Prevention, контроль и предотвращение утечек'),('CLI','интерфейс командной строки'),('GUI','графический интерфейс пользователя'),('API','программный интерфейс'),('FD','файловый дескриптор'),('PID','идентификатор процесса'),('UID','идентификатор пользователя'),('GID','идентификатор группы'),('AT-SPI','интерфейс доступности приложений'),('JSON','формат структурированного обмена данными'),('YAML','формат конфигурационных данных'),('ML','машинное обучение'),('TP, FP, FN','верное обнаружение, ложное обнаружение, пропуск'),('KiB, MiB','1024 и 1 048 576 байт соответственно')]:para(f'{a} — {b}.',indent=0)

def parse(path):
 global figure_count
 lines=path.read_text().splitlines();i=0
 while i<len(lines):
  line=lines[i].strip();i+=1
  if not line:continue
  if line.startswith('## '):heading(line[3:],2)
  elif line.startswith('# ПРИЛОЖЕНИЕ '):
   parts=[line[2:]]
   while i<len(lines) and len(parts)<3:
    if lines[i].startswith(':::subtitle '):parts.append(lines[i][12:])
    elif lines[i].strip():break
    i+=1
   heading('\n'.join(parts),1)
  elif line.startswith('# '):heading(line[2:],1)
  elif line.startswith(':::subtitle '):
   p=para(line[12:],align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.keep_with_next=True
  elif line.startswith(':::table '):
   lab,title=line[9:].split('|',1);rows=[]
   while lines[i].strip()!=':::':rows.append(lines[i].split('|'));i+=1
   i+=1;table(lab,title,rows)
  elif line.startswith(':::figure '):
   name,num,caption=line[10:].split('|');p=para('',align=WD_ALIGN_PARAGRAPH.CENTER,indent=0);p.paragraph_format.keep_with_next=True;p.add_run().add_picture(str(TMP/f'{name}.png'),width=Mm(155));para(f'Рисунок {num} — {caption}','Caption',WD_ALIGN_PARAGRAPH.CENTER);figure_count+=1
  elif line.startswith(':::equation '):
   expr,num=line[12:].split('|');p=para('',indent=0);p.paragraph_format.tab_stops.add_tab_stop(Mm(82.5),WD_TAB_ALIGNMENT.CENTER);p.paragraph_format.tab_stops.add_tab_stop(Mm(165),WD_TAB_ALIGNMENT.RIGHT);p.add_run('\t');om=OxmlElement('m:oMath');mr=OxmlElement('m:r');mt=OxmlElement('m:t');mt.text=expr;mr.append(mt);om.append(mr);p._p.append(om);p.add_run('\t('+num+')')
  elif line.startswith(':::codefile '):code((ROOT/line[12:]).read_text())
  elif line.startswith('```'):
   block=[]
   while not lines[i].startswith('```'):block.append(lines[i]);i+=1
   i+=1;code('\n'.join(block))
  elif line==':::functional':
   data=json.loads((ROOT/'docs/research/thesis_synthetic_experiment_2026-10-06.json').read_text())
   rows=[['Код','Входной случай','Ожидание / результат']]
   for r in data['functional_cases']:
    txt=r['text'] or '(пустая строка)'
    if r['id']=='P15':txt='Термин, 100 символов, контекст'
    rows.append([r['id'],txt,r['expected']+' / '+r['actual']])
   table('Д.1','Функциональный набор',rows)
  else:para(line)

for name in ['00-intro.md','01-analysis.md','02-design.md','03-implementation.md','04-evaluation.md','05-conclusion.md']:parse(CONTENT/name)
heading('СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ')
for i,ref in enumerate(json.loads((ROOT/'docs/thesis/references.json').read_text()),1):
 p=para(f'{i}. {ref}',align=WD_ALIGN_PARAGRAPH.LEFT);p.paragraph_format.keep_together=True;p.paragraph_format.first_line_indent=Mm(12.5);p.paragraph_format.space_after=Pt(0)
parse(CONTENT/'07-appendices.md')
# Cached TOC with an updateable Word field spanning entry paragraphs.
anchor=toc_anchor._p
entries=[]
for title,level,key in headings:
 if title=='ЗАДАНИЕ НА ВЫПОЛНЕНИЕ ВКР':continue
 p=D.add_paragraph(style='TOC Entry');p.paragraph_format.line_spacing=1.15;p.paragraph_format.space_after=Pt(6);p.paragraph_format.left_indent=Mm(7 if level==2 else 0);p.paragraph_format.right_indent=Mm(0);p.paragraph_format.tab_stops.add_tab_stop(Mm(165),WD_TAB_ALIGNMENT.RIGHT,WD_TAB_LEADER.DOTS)
 p.add_run(title.replace('\n',' '));p.add_run('\t'+str(PAGE_MAP.get(title,1)))
 # Contents flows naturally as the heading set grows.
 anchor.addnext(p._p);anchor=p._p;entries.append(p)
# field markers placed inside existing entries to avoid extra blank lines.
if entries:
 begin=OxmlElement('w:r');f=OxmlElement('w:fldChar');f.set(qn('w:fldCharType'),'begin');begin.append(f)
 instr=OxmlElement('w:r');it=OxmlElement('w:instrText');it.set(qn('xml:space'),'preserve');it.text=' TOC \\o "1-2" \\h \\z \\u ';instr.append(it)
 sep=OxmlElement('w:r');f=OxmlElement('w:fldChar');f.set(qn('w:fldCharType'),'separate');sep.append(f)
 for ix,e in enumerate([begin,instr,sep],1):entries[0]._p.insert(ix,e)
 end=OxmlElement('w:r');f=OxmlElement('w:fldChar');f.set(qn('w:fldCharType'),'end');end.append(f);entries[-1]._p.append(end)
abstract_count.text=f'ВКР {PAGE_COUNT or "___"} с., {figure_count} рис., {table_count} табл., 24 источника, 5 приложений.'
D.save(OUT)
(TMP/'headings.json').write_text(json.dumps(headings,ensure_ascii=False,indent=2))
print(json.dumps({'output':str(OUT),'tables':table_count,'figures':figure_count,'headings':len(headings),'words':sum(len(p.text.split()) for p in D.paragraphs)},ensure_ascii=False))
