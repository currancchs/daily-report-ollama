"""Public previews must stay inert and contain working local navigation."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

class Preview(HTMLParser):
    def __init__(self,path):
        super().__init__();self.path=path
        content=path.read_text(encoding='utf-8')
        assert 'DESIGN PREVIEW' in content
        self.feed(content)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='button':assert 'disabled' in attrs
        if tag=='form':assert attrs.get('action')=='#'
        if tag=='script':raise AssertionError('Preview should not execute scripts')
        if tag=='a':
            link=urlsplit(attrs['href'])
            assert not link.scheme and not link.netloc and not link.path.startswith('/')
            assert (self.path.parent/link.path).is_file(),attrs['href']

folder=Path(__file__).resolve().parent.parent/'examples/controls'
pages=list(folder.glob('*.html'));assert len(pages)==5
for path in pages:Preview(path)
print('PASS: five inert synthetic control pages, local links including site filters, no scripts or enabled actions')
