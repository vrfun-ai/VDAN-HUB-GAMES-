// Game Hub API v2: verified accounts, end-to-end encrypted messages, moderation, progress sync.
// Cloudflare Worker + D1. See ../README.md.
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,OPTIONS'};
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'Content-Type':'application/json',...CORS}});
const OKE=/^[^@\s]+@(gmail|outlook)\.com$/,AUTH=/^[A-Za-z0-9_-]{43}$/,CT=/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,enc=new TextEncoder();
const b64=u=>btoa(String.fromCharCode(...new Uint8Array(u))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
async function hash(pw,salt){const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256))}
async function sign(env,d){const k=await crypto.subtle.importKey('raw',enc.encode(env.SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);return b64(await crypto.subtle.sign('HMAC',k,enc.encode(d)))}
async function mk(env,e){const p=b64(enc.encode(JSON.stringify({e,x:Date.now()+30*864e5})));return p+'.'+await sign(env,p)}
async function tokEmail(env,tk){const [p,s]=tk.split('.');if(!p||!s||await sign(env,p)!==s)return null;try{const d=JSON.parse(new TextDecoder().decode(unb(p)));return d.x>Date.now()?d.e:null}catch(e){return null}}
const isAdm=(env,e)=>(env.ADMIN_EMAILS||'').toLowerCase().split(',').map(x=>x.trim()).includes(e);
async function mail(env,to,subject,text){if(!env.BREVO_KEY||!env.MAIL_FROM)throw new Error('mail');
 const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':env.BREVO_KEY,'content-type':'application/json'},body:JSON.stringify({sender:{email:env.MAIL_FROM,name:'Game Hub'},to:[{email:to}],subject,textContent:text})});if(!r.ok)throw new Error('mail')}
async function sendCode(env,DB,e,kind){const o=await DB.prepare('SELECT sent FROM codes WHERE email=? AND kind=?').bind(e,kind).first();if(o&&Date.now()-o.sent<60000)return;
 const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');
 await DB.prepare('INSERT OR REPLACE INTO codes(email,kind,hash,exp,tries,sent) VALUES(?,?,?,?,0,?)').bind(e,kind,await sign(env,e+'|'+kind+'|'+code),Date.now()+9e5,Date.now()).run();
 await mail(env,e,'Game Hub '+(kind=='verify'?'verification':'password reset')+' code','Your Game Hub code is '+code+'. It expires in 15 minutes. If you did not ask for it, ignore this email.')}
async function checkCode(env,DB,e,kind,code){const o=await DB.prepare('SELECT * FROM codes WHERE email=? AND kind=?').bind(e,kind).first();if(!o||o.exp<Date.now()||o.tries>=5)return false;
 if(await sign(env,e+'|'+kind+'|'+String(code||'').trim())!==o.hash){await DB.prepare('UPDATE codes SET tries=tries+1 WHERE email=? AND kind=?').bind(e,kind).run();return false}
 await DB.prepare('DELETE FROM codes WHERE email=? AND kind=?').bind(e,kind).run();return true}
export default{async fetch(req,env){
 if(req.method=='OPTIONS')return new Response(null,{headers:CORS});
 if(!env.SECRET)return J({error:'Server is missing its SECRET.'},500);
 const u=new URL(req.url),r=u.pathname.replace(/^\/api\//,''),DB=env.DB,now=Date.now();let b={};
 if(req.method=='POST'){try{b=await req.json()}catch(e){return J({error:'Bad request'},400)}}
 const em=String(b.email||'').trim().toLowerCase(),S=(x,n)=>String(x||'').slice(0,n);
 try{
 if(r=='lobby/ws'){if(req.headers.get('Upgrade')!='websocket')return J({error:'WebSocket required'},426);
  const e=await tokEmail(env,u.searchParams.get('token')||''),ur=e&&await DB.prepare('SELECT verified,banned FROM users WHERE email=?').bind(e).first(),code=String(u.searchParams.get('code')||'').toUpperCase(),a=u.searchParams.get('a');
  if(!ur||!ur.verified||ur.banned||!/^[A-Z0-9]{4,12}$/.test(code)||!['create','join'].includes(a)||!/^[a-z0-9_-]{0,40}$/i.test(u.searchParams.get('g')||''))return J({error:'Not allowed'},403);
  const q=new URL('https://lobby/'+code);['a','g','n'].forEach(k=>q.searchParams.set(k,u.searchParams.get(k)||''));q.searchParams.set('e',e);
  return env.LOBBY.get(env.LOBBY.idFromName(code)).fetch(new Request(q,req))}
 if(r=='signup'){const p=String(b.password||'');
  if(!OKE.test(em))return J({error:'Use a Gmail (@gmail.com) or Outlook (@outlook.com) address.'},400);
  if(!AUTH.test(p)||!b.pub||!b.wrapped||String(b.pub).length>200||String(b.wrapped).length>4000)return J({error:'Bad request'},400);
  const o=await DB.prepare('SELECT verified FROM users WHERE email=?').bind(em).first();if(o&&o.verified)return J({error:'That email already has an account.'},409);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  await DB.prepare('INSERT OR REPLACE INTO users(email,salt,hash,created,verified,pub,wrapped) VALUES(?,?,?,?,0,?,?)').bind(em,b64(salt),await hash(p,salt),now,b.pub,b.wrapped).run();
  try{await sendCode(env,DB,em,'verify')}catch(e){return J({error:'Could not send the email. Try again later.'},502)}return J({pending:1})}
 if(r=='resend'){const o=await DB.prepare('SELECT verified FROM users WHERE email=?').bind(em).first();if(o&&!o.verified){try{await sendCode(env,DB,em,'verify')}catch(e){return J({error:'Could not send the email.'},502)}}return J({ok:1})}
 if(r=='verify'){const o=await DB.prepare('SELECT 1 FROM users WHERE email=?').bind(em).first();if(!o||!await checkCode(env,DB,em,'verify',b.code))return J({error:'Wrong or expired code.'},400);
  await DB.prepare('UPDATE users SET verified=1 WHERE email=?').bind(em).run();return J({ok:1})}
 if(r=='login'){const row=await DB.prepare('SELECT * FROM users WHERE email=?').bind(em).first(),bad=()=>J({error:'Wrong email or password.'},401);
  if(!row)return bad();if(row.lockuntil>now)return J({error:'Too many tries. Wait 5 minutes.'},429);
  if(await hash(String(b.password||''),unb(row.salt))!==row.hash){const f=(row.fails||0)+1;await DB.prepare('UPDATE users SET fails=?,lockuntil=? WHERE email=?').bind(f>=5?0:f,f>=5?now+3e5:0,em).run();return bad()}
  if(!row.verified)return J({error:'Email not verified yet.',needVerify:1},403);
  if(row.banned)return J({error:'This account is banned. '+row.banreason},403);
  await DB.prepare('UPDATE users SET fails=0 WHERE email=?').bind(em).run();return J({token:await mk(env,em),email:em,wrapped:row.wrapped,admin:isAdm(env,em)})}
 if(r=='reset-request'){const o=await DB.prepare('SELECT verified FROM users WHERE email=?').bind(em).first();if(o&&o.verified){try{await sendCode(env,DB,em,'reset')}catch(e){return J({error:'Could not send the email.'},502)}}return J({ok:1})}
 if(r=='reset-confirm'){const p=String(b.password||'');if(!AUTH.test(p)||!b.pub||!b.wrapped)return J({error:'Bad request'},400);
  if(!await checkCode(env,DB,em,'reset',b.code))return J({error:'Wrong or expired code.'},400);
  const salt=crypto.getRandomValues(new Uint8Array(16));await DB.prepare('UPDATE users SET salt=?,hash=?,pub=?,wrapped=?,fails=0,lockuntil=0 WHERE email=?').bind(b64(salt),await hash(p,salt),b.pub,b.wrapped,em).run();return J({ok:1})}
 const te=await tokEmail(env,(req.headers.get('Authorization')||'').slice(7));if(!te)return J({error:'Sign in required'},401);
 const row=await DB.prepare('SELECT * FROM users WHERE email=?').bind(te).first();if(!row||!row.verified)return J({error:'Sign in required'},401);
 if(row.banned)return J({error:'This account is banned. '+row.banreason},403);
 const me=te,adm=isAdm(env,me),chatOf=id=>DB.prepare('SELECT * FROM chats WHERE id=? AND (a=? OR b=?)').bind(String(id||''),me,me).first();
 if(r=='me')return J({email:me,admin:adm});
 if(r=='chats'){const rows=(await DB.prepare('SELECT c.*,u.pub AS opub FROM chats c JOIN users u ON u.email=(CASE WHEN c.a=?1 THEN c.b ELSE c.a END) WHERE c.a=?1 OR c.b=?1 ORDER BY c.ts DESC').bind(me).all()).results;
  return J({chats:rows.map(c=>{const A=c.a==me;return{id:c.id,other:A?c.b:c.a,opub:c.opub,ts:c.ts,mine:!!(A?c.ba:c.bb),theirs:!!(A?c.bb:c.ba)}})})}
 if(r=='chat'){const to=em;if(!OKE.test(to))return J({error:'Enter a Gmail or Outlook address.'},400);if(to==me)return J({error:'That is your own address.'},400);
  const o=await DB.prepare('SELECT verified,banned FROM users WHERE email=?').bind(to).first();if(!o||!o.verified||o.banned)return J({error:'No active account with that address.'},404);
  const [x,y]=[me,to].sort(),id=x+'~'+y;await DB.prepare("INSERT OR IGNORE INTO chats(id,a,b,ba,bb,last,ts) VALUES(?,?,?,0,0,'',?)").bind(id,x,y,now).run();return J({id})}
 if(r=='msgs'){if(!await chatOf(u.searchParams.get('chat')))return J({error:'No such chat'},404);
  return J({msgs:(await DB.prepare('SELECT id,sender,text,ts FROM msgs WHERE chat=? AND id>? ORDER BY id LIMIT 100').bind(u.searchParams.get('chat'),+u.searchParams.get('after')||0).all()).results})}
 if(r=='send'){const c=await chatOf(b.chat),t=String(b.text||'');if(!c)return J({error:'No such chat'},404);
  if(!CT.test(t)||t.length>4000)return J({error:'Message rejected.'},400);if(c.ba||c.bb)return J({error:'This chat is blocked.'},403);
  const o=await DB.prepare('SELECT banned FROM users WHERE email=?').bind(c.a==me?c.b:c.a).first();if(!o||o.banned)return J({error:'That user is unavailable.'},403);
  const l=await DB.prepare('SELECT ts FROM msgs WHERE sender=? ORDER BY id DESC LIMIT 1').bind(me).first();if(l&&now-l.ts<1000)return J({error:'Slow down a little.'},429);
  await DB.prepare('INSERT INTO msgs(chat,sender,text,ts) VALUES(?,?,?,?)').bind(c.id,me,t,now).run();await DB.prepare('UPDATE chats SET ts=? WHERE id=?').bind(now,c.id).run();return J({ok:1})}
 if(r=='block'){const c=await chatOf(b.chat);if(!c)return J({error:'No such chat'},404);await DB.prepare('UPDATE chats SET '+(c.a==me?'ba':'bb')+'=? WHERE id=?').bind(b.on?1:0,c.id).run();return J({ok:1})}
 if(r=='password'){if(!AUTH.test(String(b.new||''))||!b.wrapped||String(b.wrapped).length>4000)return J({error:'Bad request'},400);
  if(await hash(String(b.old||''),unb(row.salt))!==row.hash)return J({error:'Current password is wrong.'},401);
  const salt=crypto.getRandomValues(new Uint8Array(16));await DB.prepare('UPDATE users SET salt=?,hash=?,wrapped=? WHERE email=?').bind(b64(salt),await hash(b.new,salt),b.wrapped,me).run();return J({ok:1})}
 if(r=='report'){const c=await chatOf(b.chat);if(!c)return J({error:'No such chat'},404);const ev=(Array.isArray(b.evidence)?b.evidence:[]).slice(0,30).map(x=>({id:+x.id||0,sender:S(x.sender,80),text:S(x.text,600),ts:+x.ts||0}));
  await DB.prepare('INSERT INTO reports(reporter,reported,chat,reason,evidence,ts) VALUES(?,?,?,?,?,?)').bind(me,c.a==me?c.b:c.a,c.id,S(b.reason,300),JSON.stringify(ev),now).run();return J({ok:1})}
 if(r=='progress'){if(req.method=='GET'){const o=await DB.prepare('SELECT data,updated FROM progress WHERE email=?').bind(me).first();return J(o||{data:'',updated:0})}
  const d=String(b.data||'');if(d.length>400000)return J({error:'Progress too large.'},413);await DB.prepare('INSERT OR REPLACE INTO progress(email,data,updated) VALUES(?,?,?)').bind(me,d,now).run();return J({updated:now})}
 if(r.startsWith('admin/')){if(!adm)return J({error:'Moderators only'},403);const a=r.slice(6);
  if(a=='reports'){const rows=(await DB.prepare("SELECT * FROM reports WHERE status='open' ORDER BY id DESC LIMIT 50").all()).results;return J({reports:rows.map(x=>({...x,evidence:JSON.parse(x.evidence)}))})}
  if(a=='resolve'){await DB.prepare('UPDATE reports SET status=? WHERE id=?').bind(S(b.status||'done',20),+b.id).run();return J({ok:1})}
  if(a=='delete-msg'){await DB.prepare('DELETE FROM msgs WHERE id=?').bind(+b.id).run();return J({ok:1})}
  if(a=='ban'){if(isAdm(env,em))return J({error:'Cannot ban a moderator.'},400);await DB.prepare('UPDATE users SET banned=?,banreason=? WHERE email=?').bind(b.on?1:0,S(b.reason,200),em).run();return J({ok:1})}
  if(a=='users'){const q='%'+S(u.searchParams.get('q'),60).toLowerCase()+'%';return J({users:(await DB.prepare('SELECT email,created,verified,banned,banreason FROM users WHERE email LIKE ? ORDER BY created DESC LIMIT 30').bind(q).all()).results})}
  if(a=='delete-user'){if(isAdm(env,em))return J({error:'Cannot delete a moderator.'},400);
   await DB.batch(['DELETE FROM msgs WHERE chat IN (SELECT id FROM chats WHERE a=?1 OR b=?1)','DELETE FROM chats WHERE a=?1 OR b=?1','DELETE FROM progress WHERE email=?1','DELETE FROM codes WHERE email=?1','DELETE FROM users WHERE email=?1'].map(s=>DB.prepare(s).bind(em)));return J({ok:1})}}
 return J({error:'Not found'},404);
 }catch(e){return J({error:'Server error'},500)}
}};

// One Durable Object per lobby code. Holds the room in memory and relays small state messages.
export class Lobby{
 constructor(){this.cfg=null;this.pl=new Map()}
 all(m,skip){const s=JSON.stringify(m);this.pl.forEach(p=>{if(p!==skip)try{p.ws.send(s)}catch(e){}})}
 snap(){const h=this.pl.get(this.cfg.host);this.all({t:'lobby',game:this.cfg.game,max:this.cfg.max,status:this.cfg.status,host:h?h.i:-1,players:[...this.pl.values()].map(p=>({i:p.i,n:p.name}))})}
 async fetch(req){const u=new URL(req.url),e=u.searchParams.get('e'),a=u.searchParams.get('a'),pair=new WebSocketPair(),cli=pair[0],srv=pair[1];srv.accept();
  const err=m=>{srv.send(JSON.stringify({t:'err',m}));srv.close(1000,'bye');return new Response(null,{status:101,webSocket:cli})};
  if(a=='create'){if(this.cfg&&this.pl.size)return err('That code is already in use. Pick another.');
   this.cfg={game:u.searchParams.get('g'),max:Math.min(4,Math.max(2,+u.searchParams.get('n')||4)),host:e,status:'waiting'};this.pl.clear()}
  else{if(!this.cfg||!this.pl.size)return err('No lobby with that code.');
   if(!this.pl.get(e)){if(this.cfg.status!='waiting')return err('That game has already started.');if(this.pl.size>=this.cfg.max)return err('That lobby is full.')}}
  const old=this.pl.get(e),i=old?old.i:[0,1,2,3].find(x=>![...this.pl.values()].some(p=>p.i==x));if(old)try{old.ws.close()}catch(x){}
  this.pl.set(e,{ws:srv,i,name:e.split('@')[0].slice(0,12),last:0});
  srv.send(JSON.stringify({t:'hello',i}));this.snap();
  srv.addEventListener('message',ev=>{if(String(ev.data).length>2000)return;let m;try{m=JSON.parse(ev.data)}catch(x){return}
   const p=this.pl.get(e),c=this.cfg;if(!p||p.ws!==srv||!c)return;
   if(m.t=='state'){const n=Date.now();if(n-p.last<80||typeof m.s!='object')return;p.last=n;this.all({t:'st',i:p.i,n:p.name,s:m.s},p)}
   else if(m.t=='start'&&e==c.host&&this.pl.size>=2&&c.status=='waiting'){c.status='playing';this.all({t:'start'});this.snap()}
   else if(m.t=='max'&&e==c.host&&c.status=='waiting'){c.max=Math.min(4,Math.max(2,this.pl.size,+m.n||2));this.snap()}
   else if(m.t=='kick'&&e==c.host){const q=[...this.pl.values()].find(x=>x.i==m.i);if(q&&q!==p){try{q.ws.send(JSON.stringify({t:'err',m:'You were removed from the lobby.'}));q.ws.close()}catch(x){}}}
   else if(m.t=='leave')srv.close()});
  srv.addEventListener('close',()=>{const p=this.pl.get(e);if(!p||p.ws!==srv)return;this.pl.delete(e);
   if(!this.pl.size){this.cfg=null;return}if(this.cfg.host==e)this.cfg.host=[...this.pl.keys()][0];this.snap()});
  return new Response(null,{status:101,webSocket:cli})}}
