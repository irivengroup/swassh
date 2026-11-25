"""Verify the local Markdown Wiki hierarchy, navigation, links and fences."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT=Path(__file__).resolve().parents[1]


def source_lines(text):
    """Return rendered-source lines, ignoring fenced examples for link checks."""
    marker=None
    for number,line in enumerate(text.splitlines(),1):
        fence=re.match(r'^\s*(`{3,}|~{3,})(.*)$',line)
        if fence:
            if marker is None:
                if not fence[2].strip(): raise ValueError('code fence requires a language')
                marker=fence[1][0],len(fence[1])
            elif fence[1][0]==marker[0] and len(fence[1])>=marker[1]:
                marker=None
            continue
        if marker is None: yield number,line
    if marker is not None: raise ValueError('unclosed code fence')


def anchors(text):
    found=set(); counts={}
    for _,line in source_lines(text):
        match=re.match(r'^#{1,6}\s+(.+?)\s*#*$',line)
        if match:
            title=re.sub(r'\[([^]]+)\]\([^)]+\)',r'\1',match[1])
            title=re.sub(r'<[^>]+>','',title)
            base=re.sub(r'[^\w\-\s]','',title.lower()).replace(' ','-')
            count=counts.get(base,0); counts[base]=count+1
            found.add(base+('-'+str(count) if count else ''))
    return found


class WikiVerifier:
    """Check the repository contract; no browser build or remote URL claim."""
    def __init__(self,root):
        self.root=Path(root).resolve()
        self.docs=self.root/'docs'
        self.cache={}

    def _text(self,path):
        if path not in self.cache: self.cache[path]=path.read_text(encoding='utf-8')
        return self.cache[path]

    def _links(self,path):
        for number,line in source_lines(self._text(path)):
            for value in re.findall(r'!?\[[^]\n]*\]\(([^)\n]+)\)',line):
                target=urlsplit(value)
                if target.scheme or target.netloc:
                    if target.scheme and target.scheme not in ('https','http','mailto'):
                        raise ValueError('unsupported link scheme: '+str(path)+':'+str(number))
                    continue
                if Path(unquote(target.path)).is_absolute():
                    raise ValueError('Wiki links must be relative: '+str(path))
                destination=(path.parent/unquote(target.path)).resolve() if target.path else path
                if not destination.is_relative_to(self.root) or not destination.is_file():
                    raise ValueError('missing local target: '+str(path)+':'+str(number)+' '+value)
                if target.fragment and destination.suffix=='.md' and unquote(target.fragment) not in anchors(self._text(destination)):
                    raise ValueError('missing Markdown anchor: '+str(path)+':'+str(number)+' '+value)

    def _parent(self,path):
        if path.name!='index.md': return path.parent/'index.md'
        return self.docs/'index.md' if path.parent.parent.name=='wiki.d' else path.parent.parent/'index.md'

    def _index(self,path,directory):
        text=self._text(path)
        section=re.search(r'^## Sommaire\s*\n(.*?)(?=^## |\Z)',text,re.M|re.S)
        if not section: raise ValueError('missing managed index: '+str(path))
        entries=re.findall(r'^- \[[^]\n]+\]\(([^)]+)\)',section[1],re.M)
        expected={page.name for page in directory.glob('*.md') if page.name!='index.md'}
        expected.update(child.name+'/index.md' for child in directory.iterdir()
                        if child.is_dir() and (child/'index.md').is_file())
        if path==self.docs/'index.md':
            expected={'wiki.d/'+name for name in expected}
        if len(entries)!=len(set(entries)) or set(entries)!=expected:
            raise ValueError('index must contain exactly its direct children: '+str(path))

    def verify(self):
        if {path.name for path in self.docs.iterdir()}!={'index.md','wiki.d'}:
            raise ValueError('docs root must contain only index.md and wiki.d')
        container=self.docs/'wiki.d'
        if (container/'index.md').exists(): raise ValueError('wiki.d is a container, not a duplicate portal')
        pages=sorted(self.docs.rglob('*.md'))
        portal=self.docs/'index.md'
        for path in pages:
            text=self._text(path)
            lines=list(source_lines(text))
            if sum(bool(re.match('^# ',line)) for _,line in lines)!=1:
                raise ValueError('one page title is required: '+str(path))
            parents=re.findall(r'\[Retour au Parent\]\(([^)]+)\)',text)
            if path==portal:
                if parents or 'Retour au Portail' in text: raise ValueError('portal has no parent or self-return')
                self._index(path,container)
            else:
                if len(parents)!=1 or (path.parent/parents[0]).resolve()!=self._parent(path):
                    raise ValueError('one immediate parent return is required: '+str(path))
                if 'Fil d’Ariane :' not in text or 'Retour au Portail' in text:
                    raise ValueError('breadcrumb or parent navigation invalid: '+str(path))
                if not (path.parent/'index.md').is_file(): raise ValueError('section has no index: '+str(path))
                if path.name=='index.md': self._index(path,path.parent)
                elif any(re.match('^## ',line) for _,line in lines) and '**Sommaire local**' not in text:
                    raise ValueError('page requires its local table of contents: '+str(path))
            self._links(path)
        for name in ('README.md','SECURITY.md','VALIDATION.md'):
            path=self.root/name
            if path.is_file(): self._links(path)
        return {'pages':len(pages),'cached_targets':len(self.cache),'status':'executed',
                'scope':'local Markdown paths/anchors, fences, hierarchy and navigation; remote links and rendered UI not checked'}


if __name__=='__main__':
    import json
    try:
        print(json.dumps(WikiVerifier(ROOT).verify(),ensure_ascii=False))
    except (ValueError,OSError) as error:
        print('Wiki verification refused: '+str(error),file=sys.stderr)
        raise SystemExit(1)
