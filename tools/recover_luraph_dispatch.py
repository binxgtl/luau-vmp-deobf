#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Any
import json, re

SRC=Path('luraph_interpreter_factory.luau')
A_TSV=Path('luraph_runtime_A.tsv')
OUT_JSON=Path('luraph_opcode_semantics.json')
OUT_TXT=Path('luraph_opcode_semantics.txt')

KEYWORDS={'if','then','elseif','else','end','while','do','for','in','repeat','until','function','local','return','break','continue','and','or','not','true','false','nil'}
MULTI=['...','==','~=','<=','>=','+=','-=','*=','/=','//=','%=','^=','..=','->','::','..','//']

@dataclass
class Tok:
    v:str; start:int; end:int; kind:str=''


def lex(s:str)->List[Tok]:
    out=[]; i=0; n=len(s)
    while i<n:
        c=s[i]
        if c.isspace(): i+=1; continue
        if s.startswith('--',i):
            if s.startswith('--[[',i):
                j=s.find(']]',i+4); i=n if j<0 else j+2
            else:
                j=s.find('\n',i+2); i=n if j<0 else j+1
            continue
        if c in ('"',"'"):
            q=c; j=i+1
            while j<n:
                if s[j]=='\\': j+=2; continue
                if s[j]==q: j+=1; break
                j+=1
            out.append(Tok(s[i:j],i,j,'str')); i=j; continue
        if c=='[' and i+1<n and s[i+1]=='[':
            j=s.find(']]',i+2); j=n if j<0 else j+2
            out.append(Tok(s[i:j],i,j,'str')); i=j; continue
        m=re.match(r'(?:0[xX][0-9A-Fa-f]+|(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)',s[i:])
        if m:
            j=i+len(m.group(0)); out.append(Tok(s[i:j],i,j,'num')); i=j; continue
        m=re.match(r'[A-Za-z_][A-Za-z0-9_]*',s[i:])
        if m:
            j=i+len(m.group(0)); v=s[i:j]; out.append(Tok(v,i,j,'kw' if v in KEYWORDS else 'id')); i=j; continue
        hit=None
        for op in MULTI:
            if s.startswith(op,i): hit=op; break
        if hit:
            out.append(Tok(hit,i,i+len(hit),'op')); i+=len(hit); continue
        out.append(Tok(c,i,i+1,'op')); i+=1
    return out

@dataclass
class Node: pass
@dataclass
class Raw(Node):
    toks:List[Tok]
@dataclass
class If(Node):
    branches:List[Tuple[List[Tok],List[Node]]]
    else_body:Optional[List[Node]]
@dataclass
class While(Node):
    cond:List[Tok]; body:List[Node]
@dataclass
class For(Node):
    header:List[Tok]; body:List[Node]
@dataclass
class Repeat(Node):
    body:List[Node]; cond:List[Tok]
@dataclass
class Do(Node): body:List[Node]
@dataclass
class Function(Node):
    prefix:List[Tok]; body:List[Node]

class Parser:
    def __init__(self,toks:List[Tok]): self.t=toks; self.i=0
    def peek(self,k=0): return self.t[self.i+k].v if self.i+k<len(self.t) else None
    def take(self,v=None):
        t=self.t[self.i]
        if v is not None and t.v!=v: raise SyntaxError(f'expected {v} got {t.v} @{self.i}')
        self.i+=1; return t
    def collect_until(self,stop:str)->List[Tok]:
        out=[]; par=br=brace=0
        while self.i<len(self.t):
            v=self.peek()
            if v==stop and par==br==brace==0: break
            tok=self.take(); out.append(tok)
            if tok.v=='(': par+=1
            elif tok.v==')': par-=1
            elif tok.v=='[': br+=1
            elif tok.v==']': br-=1
            elif tok.v=='{': brace+=1
            elif tok.v=='}': brace-=1
        return out
    def parse_block(self,stops:set[str])->List[Node]:
        nodes=[]
        while self.i<len(self.t) and self.peek() not in stops:
            nodes.append(self.parse_stmt())
            while self.peek()==';': self.take(';')
        return nodes
    def parse_stmt(self)->Node:
        v=self.peek()
        if v=='if': return self.parse_if()
        if v=='while': return self.parse_while()
        if v=='for': return self.parse_for()
        if v=='repeat': return self.parse_repeat()
        if v=='do': return self.parse_do()
        if v=='function' or (v=='local' and self.peek(1)=='function'): return self.parse_function_stmt()
        return self.parse_raw()
    def parse_if(self)->If:
        self.take('if'); cond=self.collect_until('then'); self.take('then')
        branches=[(cond,self.parse_block({'elseif','else','end'}))]
        while self.peek()=='elseif':
            self.take(); c=self.collect_until('then'); self.take('then')
            branches.append((c,self.parse_block({'elseif','else','end'})))
        eb=None
        if self.peek()=='else': self.take(); eb=self.parse_block({'end'})
        self.take('end')
        return If(branches,eb)
    def parse_while(self)->While:
        self.take('while'); c=self.collect_until('do'); self.take('do')
        b=self.parse_block({'end'}); self.take('end'); return While(c,b)
    def parse_for(self)->For:
        self.take('for'); h=self.collect_until('do'); self.take('do')
        b=self.parse_block({'end'}); self.take('end'); return For(h,b)
    def parse_repeat(self)->Repeat:
        self.take('repeat'); b=self.parse_block({'until'}); self.take('until')
        c=self.parse_raw().toks; return Repeat(b,c)
    def parse_do(self)->Do:
        self.take('do'); b=self.parse_block({'end'}); self.take('end'); return Do(b)
    def parse_function_stmt(self)->Function:
        pref=[]
        if self.peek()=='local': pref.append(self.take())
        pref.append(self.take('function'))
        par=0
        while self.i<len(self.t):
            tok=self.take(); pref.append(tok)
            if tok.v=='(': par+=1
            elif tok.v==')':
                par-=1
                if par==0: break
        b=self.parse_block({'end'}); self.take('end'); return Function(pref,b)
    def parse_raw(self)->Raw:
        out=[]; par=br=brace=0; func_depth=0
        while self.i<len(self.t):
            v=self.peek()
            if par==br==brace==0 and func_depth==0 and (v==';' or v in {'elseif','else','end','until'}): break
            tok=self.take(); out.append(tok)
            if tok.v=='(': par+=1
            elif tok.v==')': par-=1
            elif tok.v=='[': br+=1
            elif tok.v==']': br-=1
            elif tok.v=='{': brace+=1
            elif tok.v=='}': brace-=1
            elif tok.v=='function': func_depth+=1
            elif tok.v=='end' and func_depth>0: func_depth-=1
        if not out and self.i<len(self.t):
            out.append(self.take())
        return Raw(out)

@dataclass(frozen=True)
class AVal:
    kind:str; value:Any; cls:Tuple[int,...]; truth:bool


def load_A(path:Path):
    vals={}
    for line in path.read_text().splitlines():
        i,typ,text,truth,cls=line.split('\t')
        i=int(i); cl=tuple(map(int,cls.split(','))) if cls else ()
        if typ=='nil': val=None
        elif typ=='boolean': val=(text=='true')
        elif typ=='number': val=float(text)
        else: val=('obj',cl)
        vals[i]=AVal(typ,val,cl,truth=='true')
    return vals

UNKNOWN=object()
class KnownFunc:
    def __init__(self,name): self.name=name
    def __repr__(self): return f'<fn {self.name}>'
class KnownTable:
    def __init__(self,name): self.name=name
    def __repr__(self): return f'<table {self.name}>'

HELPERS={
  5:'math.modf',6:'math.pi',7:'bit32.bor',8:'bit32.bxor',9:'string.byte',
  10:'bit32.countrz',11:'bit32.band',12:'bit32.rshift',13:'bit32.countlz',
  14:'string.unpack',15:'bit32.lrotate',16:'math.ceil',17:'string.len',
  18:'string.packsize',19:'bit32.lshift',20:'bit32.rrotate',21:'math.floor',22:'bit32.bnot'
}

def u32(x): return int(x) & 0xffffffff
def apply_known_func(fn,args):
    if any(a is UNKNOWN for a in args): return UNKNOWN
    n=fn.name
    try:
        if n=='bit32.bor':
            r=0
            for a in args:r|=u32(a)
            return u32(r)
        if n=='bit32.bxor':
            r=0
            for a in args:r^=u32(a)
            return u32(r)
        if n=='bit32.band':
            r=0xffffffff
            for a in args:r&=u32(a)
            return u32(r)
        if n=='bit32.bnot': return u32(~u32(args[0]))
        if n=='bit32.lshift': return u32(u32(args[0]) << (int(args[1]) & 31))
        if n=='bit32.rshift': return u32(args[0]) >> (int(args[1]) & 31)
        if n=='bit32.lrotate':
            x=u32(args[0]); k=int(args[1])&31; return u32((x<<k)|(x>>(32-k if k else 32)))
        if n=='bit32.rrotate':
            x=u32(args[0]); k=int(args[1])&31; return u32((x>>k)|(x<<(32-k if k else 32)))
        if n=='bit32.countlz':
            x=u32(args[0]); return 32 if x==0 else 32-x.bit_length()
        if n=='bit32.countrz':
            x=u32(args[0]); return 32 if x==0 else (x & -x).bit_length()-1
        if n=='math.floor': import math; return math.floor(args[0])
        if n=='math.ceil': import math; return math.ceil(args[0])
        if n=='math.pi': import math; return math.pi
        if n=='math.modf': import math; return math.modf(args[0])[1]
        if n=='string.len': return len(args[0])
        if n=='string.byte':
            st=args[0]; i=int(args[1]) if len(args)>1 else 1; return ord(st[i-1])
    except Exception: return UNKNOWN
    return UNKNOWN

class ExprParser:
    def __init__(self,toks:Sequence[Tok],X:int,Avals,env=None): self.t=list(toks); self.i=0; self.X=X; self.A=Avals; self.env=env or {}
    def peek(self,k=0): return self.t[self.i+k].v if self.i+k<len(self.t) else None
    def take(self): t=self.t[self.i]; self.i+=1; return t
    def parse(self,minbp=0, stop=None):
        stop=stop or set()
        if self.i>=len(self.t) or self.peek() in stop: return UNKNOWN
        tok=self.take(); v=tok.v
        if v=='(':
            left=self.parse(0,{')'})
            if self.peek()==')': self.take()
        elif v=='not':
            a=self.parse(90,stop); left=UNKNOWN if a is UNKNOWN else (not truthy(a))
        elif v=='-':
            a=self.parse(90,stop); left=UNKNOWN if a is UNKNOWN or not isinstance(a,(int,float)) else -a
        elif v=='#':
            a=self.parse(90,stop); left=UNKNOWN if a is UNKNOWN else (len(a) if hasattr(a,'__len__') else UNKNOWN)
        elif v=='X': left=self.X
        elif v=='true': left=True
        elif v=='false': left=False
        elif v=='nil': left=None
        elif tok.kind=='num':
            try: left=int(v,0) if not any(c in v for c in '.eE') else float(v)
            except: left=UNKNOWN
        elif tok.kind=='str':
            try: left=bytes(v[1:-1],'utf8').decode('unicode_escape')
            except: left=v[1:-1]
        elif v=='A': left=KnownTable('A')
        elif tok.kind in ('id','kw') and v in self.env: left=self.env[v]
        else: left=UNKNOWN
        while self.i<len(self.t):
            op=self.peek()
            if op=='[':
                self.take(); key=self.parse(0,{']'});
                if self.peek()==']': self.take()
                if isinstance(left,KnownTable) and left.name=='A' and isinstance(key,(int,float)):
                    idx=int(key)
                    if idx==32: left=KnownTable('A32')
                    else:
                        av=self.A.get(idx); left=UNKNOWN if av is None else av.value
                elif isinstance(left,KnownTable) and left.name=='A32' and isinstance(key,(int,float)):
                    name=HELPERS.get(int(key)); left=KnownFunc(name) if name and name!='math.pi' else (apply_known_func(KnownFunc(name),[]) if name else UNKNOWN)
                else: left=UNKNOWN
                continue
            if op=='(':
                self.take(); args=[]
                if self.peek()!=')':
                    while self.i<len(self.t):
                        args.append(self.parse(0,{',',')'}))
                        if self.peek()==',': self.take(); continue
                        break
                if self.peek()==')': self.take()
                left=apply_known_func(left,args) if isinstance(left,KnownFunc) else UNKNOWN
                continue
            break
        prec={'or':10,'and':20,'==':30,'~=':30,'<':30,'>':30,'<=':30,'>=':30,'+':40,'-':40,'*':50,'/':50,'%':50,'//':50,'^':60}
        while self.i<len(self.t):
            op=self.peek()
            if op in stop: break
            bp=prec.get(op,-1)
            if bp<minbp: break
            self.take(); right=self.parse(bp+(0 if op=='^' else 1),stop)
            left=applyop(op,left,right)
        return left

def truthy(v): return not (v is None or v is False)
def applyop(op,a,b):
    if op=='and':
        if a is UNKNOWN: return UNKNOWN
        return b if truthy(a) else a
    if op=='or':
        if a is UNKNOWN: return UNKNOWN
        return a if truthy(a) else b
    if a is UNKNOWN or b is UNKNOWN: return UNKNOWN
    try:
        if op=='==': return a==b
        if op=='~=': return a!=b
        if op=='<': return a<b
        if op=='>': return a>b
        if op=='<=': return a<=b
        if op=='>=': return a>=b
        if op=='+': return a+b
        if op=='-': return a-b
        if op=='*': return a*b
        if op=='/': return a/b
        if op=='//': return a//b
        if op=='%': return a%b
        if op=='^': return a**b
    except Exception: return UNKNOWN
    return UNKNOWN

def eval_cond(toks,X,A,env=None):
    try:
        p=ExprParser(toks,X,A,env); v=p.parse()
        if p.i!=len(p.t): return UNKNOWN
        return UNKNOWN if v is UNKNOWN else truthy(v)
    except Exception:
        return UNKNOWN


def _simple_assign(raw:Raw,X,A,env):
    ts=raw.toks
    if not ts: return
    i=0
    if ts[0].v=='local': i=1
    if i+2<=len(ts)-1 and ts[i].kind in ('id','kw') and ts[i+1].v in ('=','+=','-=','*=','/=','//=','%='):
        name=ts[i].v; op=ts[i+1].v; rhs=ts[i+2:]
        try:
            p=ExprParser(rhs,X,A,env); val=p.parse()
            if p.i!=len(p.t): val=UNKNOWN
        except Exception: val=UNKNOWN
        if op=='=': env[name]=val
        else:
            old=env.get(name,UNKNOWN)
            env[name]=applyop(op[0] if op!='//=' else '//',old,val)
    elif len(ts)>=2 and ts[0].v=='local' and ts[1].kind in ('id','kw'):
        env[ts[1].v]=UNKNOWN

def specialize(nodes:List[Node],X:int,A,env=None)->List[Node]:
    env=dict(env or {'q':('closure_q',)})
    out=[]
    for n in nodes:
        if isinstance(n,Raw):
            _simple_assign(n,X,A,env)
            out.append(n)
        elif isinstance(n,If):
            picked=False; unknown=[]
            for cond,body in n.branches:
                v=eval_cond(cond,X,A,env)
                if v is True:
                    out.extend(specialize(body,X,A,dict(env))); picked=True; break
                elif v is UNKNOWN:
                    unknown.append((cond,specialize(body,X,A,dict(env))))
            if picked: continue
            eb=specialize(n.else_body or [],X,A,dict(env)) if n.else_body is not None else None
            if unknown:
                out.append(If(unknown,eb))
                env={k:v for k,v in env.items() if k in ('q',)}
            elif eb is not None:
                out.extend(eb)
        elif isinstance(n,While):
            v=eval_cond(n.cond,X,A,env)
            b=specialize(n.body,X,A,{'q':env.get('q',('closure_q',))})
            if v is False: continue
            out.append(While(n.cond,b)); env={k:v for k,v in env.items() if k in ('q',)}
        elif isinstance(n,For): out.append(For(n.header,specialize(n.body,X,A,{'q':env.get('q',('closure_q',))})))
        elif isinstance(n,Repeat): out.append(Repeat(specialize(n.body,X,A,{'q':env.get('q',('closure_q',))}),n.cond)); env={k:v for k,v in env.items() if k in ('q',)}
        elif isinstance(n,Do): out.append(Do(specialize(n.body,X,A,dict(env))))
        elif isinstance(n,Function): out.append(Function(n.prefix,specialize(n.body,X,A,dict(env))))
        else: out.append(n)
    return out


def toktext(ts:Sequence[Tok])->str:
    out=''; prev=None
    for t in ts:
        v=t.v
        if out and prev and ((prev.kind in ('id','kw','num') and t.kind in ('id','kw','num'))): out+=' '
        out+=v; prev=t
    return out

def render(nodes:List[Node],ind=0)->List[str]:
    p='    '*ind; out=[]
    for n in nodes:
        if isinstance(n,Raw):
            txt=toktext(n.toks)
            if txt: out.append(p+txt+';')
        elif isinstance(n,If):
            for j,(c,b) in enumerate(n.branches):
                out.append(p+('if ' if j==0 else 'elseif ')+toktext(c)+' then')
                out+=render(b,ind+1)
            if n.else_body is not None:
                out.append(p+'else'); out+=render(n.else_body,ind+1)
            out.append(p+'end')
        elif isinstance(n,While):
            out.append(p+'while '+toktext(n.cond)+' do'); out+=render(n.body,ind+1); out.append(p+'end')
        elif isinstance(n,For):
            out.append(p+'for '+toktext(n.header)+' do'); out+=render(n.body,ind+1); out.append(p+'end')
        elif isinstance(n,Repeat):
            out.append(p+'repeat'); out+=render(n.body,ind+1); out.append(p+'until '+toktext(n.cond))
        elif isinstance(n,Do):
            out.append(p+'do'); out+=render(n.body,ind+1); out.append(p+'end')
        elif isinstance(n,Function):
            out.append(p+toktext(n.prefix)); out+=render(n.body,ind+1); out.append(p+'end')
    return out


def count_unknown_ifs(nodes):
    c=0
    for n in nodes:
        if isinstance(n,If): c+=1+sum(count_unknown_ifs(b) for _,b in n.branches)+(count_unknown_ifs(n.else_body or []))
        elif hasattr(n,'body'): c+=count_unknown_ifs(n.body)
    return c

def main():
    s=SRC.read_text()
    toks=lex(s)
    wi=None
    for i in range(len(toks)-8):
        if toks[i].v=='while' and toks[i+1].v=='true' and toks[i+2].v=='do' and toks[i+3].v=='local' and toks[i+4].v=='X':
            wi=i; break
    if wi is None: raise RuntimeError('dispatcher while not found')
    parser=Parser(toks); parser.i=wi
    w=parser.parse_while()
    print('parsed while statements',len(w.body),'token index',parser.i,'/',len(toks))
    A=load_A(A_TSV)
    results={}
    report=[]
    core=w.body[1:-1]
    for x in range(256):
        sp=specialize(core,x,A)
        lines=render(sp)
        text='\n'.join(lines)
        results[str(x)]={'source':text,'unknown_ifs':count_unknown_ifs(sp),'lines':len(lines)}
        report.append(f'-- opcode {x} | unknown_if={results[str(x)]["unknown_ifs"]}\n{text}\n')
    OUT_JSON.write_text(json.dumps(results,indent=2,ensure_ascii=False))
    OUT_TXT.write_text('\n'.join(report))
    print('wrote',OUT_JSON,OUT_TXT)
    from collections import Counter
    print('unique semantics',len(set(v['source'] for v in results.values())))
    print('unknown-if stats',Counter(v['unknown_ifs'] for v in results.values()))
    for x in range(20): print('\nOP',x,'\n',results[str(x)]['source'][:500])
if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser(description='Recover all opcode semantics from a sample-local Luraph dispatcher')
    ap.add_argument('factory', help='extracted interpreter factory source')
    ap.add_argument('runtime_facts', help='runtime A-table facts TSV (index/type/value/truth/equality-class)')
    ap.add_argument('-o','--output', default='luraph_opcode_semantics.json')
    ap.add_argument('--text-output', default='luraph_opcode_semantics.txt')
    ns=ap.parse_args()
    SRC=Path(ns.factory); A_TSV=Path(ns.runtime_facts)
    OUT_JSON=Path(ns.output); OUT_TXT=Path(ns.text_output)
    main()
