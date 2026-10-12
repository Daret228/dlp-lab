"""Update cached TOC pages from pdftotext -layout output, then rebuild DOCX."""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
work = root / 'build/thesis'
pages = [p for p in Path(sys.argv[1]).read_text().split('\f') if p.strip()]
normalize = lambda value: ' '.join(value.split())
mapping = {'_pages': len(pages)}
for title, _, _ in json.loads((work / 'headings.json').read_text()):
    hits = [i + 1 for i, page in enumerate(pages)
            if len(re.findall(r'\.{3,}', page)) < 2
            and normalize(title) in normalize(page)]
    if not hits:
        raise ValueError(f'Heading not found: {title}')
    mapping[title] = hits[-1]
(work / 'page_map.json').write_text(json.dumps(mapping, ensure_ascii=False, indent=2))
print(f'Mapped {len(mapping) - 1} headings across {len(pages)} pages')
