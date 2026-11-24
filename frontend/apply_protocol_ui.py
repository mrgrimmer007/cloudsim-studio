"""Adds protocol security fields, link protocols and 'Apply fix' buttons to CloudSim Studio.
Usage (from the frontend folder):  python apply_protocol_ui.py index.html
Makes index.html.bak first. Aborts without changing anything if any anchor is missing."""
import pathlib, shutil, sys

EDITS = []
def E(old, new): EDITS.append((old, new))

# 1. styles
E(""".fix{color:var(--mute);font-size:12px}""",
  """.fix{color:var(--mute);font-size:12px}
.fx{margin-top:4px;padding:2px 8px;font-size:12px}""")

# 2. option lists
E("""const rg=['region','Region','sel',R],lg=['logging','Logging','chk'];""",
  """const rg=['region','Region','sel',R],lg=['logging','Logging','chk'];
const TLS=['1.3','1.2','1.1','1.0'],CERT=['valid','self-signed','expired'];""")

# 3. new editable fields
E("""['rate','Rate limit per minute','num'],lg]}""",
  """['rate','Rate limit per minute','num'],['tls','TLS version','sel',TLS],['cert','Certificate','sel',CERT],['token_ttl','Token lifetime (minutes)','num'],lg]}""")
E("""['proto','Protocol','sel',['HTTPS','HTTP']]]}""",
  """['proto','Protocol','sel',['HTTPS','HTTP']],['tls','TLS version','sel',TLS],['hsts','HSTS enabled','chk'],['cert','Certificate','sel',CERT]]}""")
E("""['ssh_open','SSH open to 0.0.0.0/0','chk'],""",
  """['ssh_open','SSH open to 0.0.0.0/0','chk'],['ssh_auth','SSH login method','sel',['key','password']],""")
E("""['encrypted','Encrypted','chk'],""",
  """['encrypted','Encrypted','chk'],['tls_required','Require TLS connections','chk'],""")

# 4. secure defaults for new components
E("""apigw:{region:'mumbai',auth:'none',rate:10,logging:false}""",
  """apigw:{region:'mumbai',auth:'none',rate:10,tls:'1.2',cert:'valid',token_ttl:15,logging:false}""")
E("""lb:{region:'mumbai',proto:'HTTPS'}""",
  """lb:{region:'mumbai',proto:'HTTPS',tls:'1.2',hsts:true,cert:'valid'}""")
E("""ssh_open:false,subnet:'private'""", """ssh_open:false,ssh_auth:'key',subnet:'private'""")
E("""encrypted:false,subnet:'private'""", """encrypted:false,tls_required:true,subnet:'private'""")

# 5. links can carry a protocol; make the insecure example show the new findings
E("""const link=(a,b)=>S.edges.push({from:a.id,to:b.id});""",
  """const link=(a,b,p)=>S.edges.push(p?{from:a.id,to:b.id,proto:p}:{from:a.id,to:b.id});""")
E("""ssh_open:true,iam:'admin'""", """ssh_open:true,ssh_auth:'password',iam:'admin'""")
E("""{c:{public:true,subnet:'public'}}""", """{c:{public:true,tls_required:false,subnet:'public'}}""")
E("""link(i,v);link(v,d)}""", """link(i,v);link(v,d,'HTTP')}""")

# 6. browser-side copies of SEC-13..SEC-19 (used when the backend is not connected)
E("""const P={critical:30,high:20,medium:10,low:5},o=['critical','high','medium','low'];""",
  """vms.forEach(v=>{if(v.c.ssh_auth==='password')add('SEC-16','high',v,'allows SSH password login','Use key-based SSH, disable passwords, and reach the VM through a bastion host or VPN.')});
N.filter(n=>n.type==='db'&&n.c.tls_required===false).forEach(d=>add('SEC-17','medium',d,'accepts connections without TLS','Require TLS for all database connections.'));
N.filter(n=>n.type==='lb'||n.type==='apigw').forEach(n=>{const c=n.c;
if(['1.0','1.1'].includes(String(c.tls)))add('SEC-13','high',n,'allows outdated TLS '+c.tls,'Require TLS 1.2 or higher, and prefer TLS 1.3.');else if(String(c.tls)==='1.3')G.push(n.name+' uses TLS 1.3');
if(c.proto==='HTTPS'&&c.hsts===false)add('SEC-14','low',n,'serves HTTPS without HSTS','Enable HSTS so browsers refuse plain HTTP.');
if(['self-signed','expired'].includes(c.cert))add('SEC-18','high',n,'uses a '+c.cert+' certificate','Use a certificate from a trusted CA and enable automatic renewal.')});
E.forEach(e=>{const a=nb(e.from),b=nb(e.to);if(a&&b&&a.type!=='internet'&&b.type!=='internet'&&String(e.proto||'').toUpperCase()==='HTTP')add('SEC-15','medium',b,'receives plaintext HTTP from '+a.name,'Use TLS on this link, and mutual TLS (mTLS) for service-to-service traffic.')});
N.filter(n=>n.type==='apigw'&&String(n.c.auth).toLowerCase()==='jwt'&&(+n.c.token_ttl||0)>60).forEach(g=>add('SEC-19','medium',g,'issues tokens valid for '+g.c.token_ttl+' minutes','Use short-lived access tokens (15 minutes or less) with refresh tokens.'));
const P={critical:30,high:20,medium:10,low:5},o=['critical','high','medium','low'];""")

# 7. per-link protocol selector in the Edit tab + one-click fixes
E("""function secPane(){""",
  """function edgeCfg(n){const ins=S.edges.map((e,i)=>({e,i})).filter(x=>x.e.to===n.id&&nb(x.e.from)&&nb(x.e.from).type!=='internet');
return ins.length?'<p class="hint">Incoming connections</p>'+ins.map(({e,i})=>`<label>From ${esc(nb(e.from).name)}<select data-e="${i}">${['(not set)','HTTPS','HTTP'].map(x=>`<option ${x===(e.proto||'(not set)')?'selected':''}>${x}</option>`).join('')}</select></label>`).join(''):''}
const FIX={
'SEC-01':n=>{n.c.public=false;S.edges=S.edges.filter(e=>!(e.to===n.id&&(nb(e.from)||{}).type==='internet'))},
'SEC-02':n=>{n.c.ssh_open=false},'SEC-03':n=>{n.c.public_ip=false},'SEC-04':n=>{n.c.proto='HTTPS'},
'SEC-05':n=>{n.c.encrypted=true},'SEC-06':n=>{n.c.auth='jwt'},'SEC-07':n=>{n.c.iam='least_privilege'},
'SEC-08':n=>{n.c.logging=true},'SEC-10':n=>{n.c.subnet='private'},'SEC-11':n=>{n.c.rate=100},
'SEC-13':n=>{n.c.tls='1.3'},'SEC-14':n=>{n.c.hsts=true},
'SEC-15':n=>{S.edges.forEach(e=>{if(e.to===n.id&&String(e.proto).toUpperCase()==='HTTP')e.proto='HTTPS'})},
'SEC-16':n=>{n.c.ssh_auth='key'},'SEC-17':n=>{n.c.tls_required=true},'SEC-18':n=>{n.c.cert='valid'},'SEC-19':n=>{n.c.token_ttl=15}};
function secPane(){""")
E("""return h+(n.type!=='internet'?""", """h+=edgeCfg(n);return h+(n.type!=='internet'?""")
E("""r.F.forEach(f=>h+=""",
  """if(r.F.some(f=>FIX[f.id]))h+='<button class="fx" data-act="fixall">Apply all fixes</button>';r.F.forEach((f,i)=>h+=""")
E("""${f.fix}</div></div>""",
  """${f.fix}</div>${FIX[f.id]?`<button class="fx" data-act="fix" data-i="${i}">Apply fix</button>`:''}</div>""")
E("""$('#pane').addEventListener('change',e=>{const n=nb(S.sel)""",
  """$('#pane').addEventListener('change',e=>{const ei=e.target.dataset.e;if(ei!==undefined){const ed=S.edges[+ei];if(ed){if(e.target.value==='(not set)')delete ed.proto;else ed.proto=e.target.value;refresh()}return}const n=nb(S.sel)""")
E("""if(a==='fail'){const n=nb(S.sel);n.failed=!n.failed;refresh()}""",
  """if(a==='fail'){const n=nb(S.sel);n.failed=!n.failed;refresh()}
if(a==='fix'){const f=sec().F[+e.target.dataset.i];if(f&&FIX[f.id]){FIX[f.id](f.n);refresh()}}
if(a==='fixall'){sec().F.forEach(f=>FIX[f.id]&&FIX[f.id](f.n));refresh()}""")

# 8. give older saved designs the new default fields
E("""const nb=id=>S.nodes.find(n=>n.id===id);""",
  """const nb=id=>S.nodes.find(n=>n.id===id);
const mig=()=>S.nodes.forEach(n=>{n.c={...D[n.type],...n.c}});""")
E("""S.nodes=s.nodes;S.edges=s.edges;uid=s.uid||100;refresh()""", """S.nodes=s.nodes;S.edges=s.edges;uid=s.uid||100;mig();refresh()""")
E("""S.nodes=m.nodes;S.edges=m.edges;uid=Math.max(""", """S.nodes=m.nodes;S.edges=m.edges;mig();uid=Math.max(""")

if __name__ == "__main__":
    p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "index.html")
    s = p.read_text(encoding="utf-8")
    if "SEC-19" in s:
        sys.exit("Already patched. Nothing to do.")
    for i, (old, new) in enumerate(EDITS, 1):
        n = s.count(old)
        if n != 1:
            sys.exit(f"Edit {i} failed: anchor found {n} times (expected 1):\n{old[:90]}\nNothing was changed.")
        s = s.replace(old, new)
    shutil.copy(p, str(p) + ".bak")
    p.write_text(s, encoding="utf-8")
    print(f"Patched {p} ({len(EDITS)} edits). Backup: {p}.bak")
