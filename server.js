const express=require('express'),helmet=require('helmet'),rl=require('express-rate-limit'),bcrypt=require('bcryptjs'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const {ADMIN_USER='owner',ADMIN_HASH,SECRET,PORT=3000,NODE_ENV}=process.env;
if(!ADMIN_HASH||!SECRET||SECRET.length<32){console.error('Set ADMIN_HASH and a 32+ char SECRET in .env (see .env.example)');process.exit(1)}
const DEFAULT={ig:"jasautodetailing",disc:20,hh:"Your car,|back to showroom.",hp:"Ceramic coating, paint correction and deep interior detailing at two shops.",svcs:"Interior only, Not sure, advise me",times:"9:00, 10:00, 11:00, 12:00, 13:00, 14:00, 15:00, 16:00, 17:00, 18:00",
shops:[{name:"JAS Auto Detailing, Shop 1",addr:"Shop 1 address",phone:"+10000000001",wa:"10000000001",hrs:"9:00 am to 7:00 pm",review:""},{name:"JAS Auto Detailing, Shop 2",addr:"Shop 2 address",phone:"+10000000002",wa:"10000000002",hrs:"9:00 am to 7:00 pm",review:""}],
pkgs:[{name:"Express Detail",price:"79",feat:"Hand wash and dry, Interior vacuum, Tire shine",best:""},{name:"Full Detail",price:"189",feat:"Everything in Express, Clay bar and wax, Deep interior clean",best:"1"},{name:"Ceramic Coating",price:"699",feat:"Paint correction, 2-year ceramic coating, Glass coating",best:""}],
plans:[{name:"Silver Plan",price:"49",feat:"1 wash per month, 10% off add-ons",best:""},{name:"Gold Plan",price:"99",feat:"2 washes and 1 interior per month, Priority booking",best:"1"},{name:"Platinum Plan",price:"179",feat:"Weekly wash, Monthly full detail, Free pickup",best:""}],
team:[{name:"Team member",role:"Lead detailer",tags:"Ceramic certified, Paint correction"}],reviews:[{name:"Customer",text:"Sample review. Replace in the dashboard.",stars:"5",type:"Ceramic coating",featured:""}],gal:[{cap:"Before and after",img:""}]};
const FILE=path.join(__dirname,'data.json');
let db;try{db=JSON.parse(fs.readFileSync(FILE))}catch{db={content:DEFAULT,bookings:[]}}
const save=()=>{fs.writeFileSync(FILE+'.tmp',JSON.stringify(db));fs.renameSync(FILE+'.tmp',FILE)};
const b64=b=>Buffer.from(b).toString('base64url'),mac=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const mint=()=>{const p=b64(JSON.stringify({exp:Date.now()+8*36e5,csrf:crypto.randomBytes(16).toString('hex')}));return p+'.'+mac(p)};
function read(req){const m=(req.headers.cookie||'').match(/(?:^|; )sid=([^;]+)/);if(!m)return null;const[p,s]=m[1].split('.');if(!p||!s)return null;
const a=Buffer.from(mac(p)),b=Buffer.from(s);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;try{const d=JSON.parse(Buffer.from(p,'base64url'));return d.exp>Date.now()?d:null}catch{return null}}
const auth=(req,res,next)=>{const s=read(req);if(!s)return res.status(401).json({error:'auth'});
if(req.method!=='GET'&&req.get('x-csrf')!==s.csrf)return res.status(403).json({error:'csrf'});req.s=s;next()};
const app=express();app.set('trust proxy',1);app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'",'https://fonts.googleapis.com'],fontSrc:['https://fonts.gstatic.com'],imgSrc:["'self'",'data:'],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"],baseUri:["'self'"],formAction:["'self'"],upgradeInsecureRequests:NODE_ENV==='production'?[]:null}},hsts:NODE_ENV==='production'}));
app.use(express.json({limit:'10mb'}));
app.use((req,res,next)=>{if(req.path.startsWith('/admin')||req.path.startsWith('/api/admin'))res.set({'X-Robots-Tag':'noindex','Cache-Control':'no-store'});next()});
const lim=(n,m)=>rl({windowMs:n*6e4,limit:m,standardHeaders:true,legacyHeaders:false});
const str=(v,n)=>typeof v==='string'?v.trim().slice(0,n):'';
app.get('/api/content',(q,r)=>r.json(db.content));
app.post('/api/bookings',lim(60,10),(q,r)=>{const b=q.body||{},o={shop:str(b.shop,80),svc:str(b.svc,80),date:str(b.date,10),time:str(b.time,8),name:str(b.name,80),phone:str(b.phone,20),note:str(b.note,300)};
if(!o.name||!/^[0-9+() -]{6,20}$/.test(o.phone)||!/^\d{4}-\d{2}-\d{2}$/.test(o.date)||!o.svc)return r.status(400).json({error:'invalid'});
if(db.bookings.length>=5000)return r.status(503).json({error:'full'});
db.bookings.push({id:crypto.randomUUID(),...o,status:'new',at:new Date().toISOString()});save();r.json({ok:true})});
app.post('/api/login',lim(15,5),(q,r)=>{const u=str(q.body?.user,60),p=str(q.body?.pass,200);
const ok=bcrypt.compareSync(p,ADMIN_HASH)&&u===ADMIN_USER;if(!ok)return r.status(401).json({error:'Wrong username or password'});
r.cookie('sid',mint(),{httpOnly:true,sameSite:'strict',secure:NODE_ENV==='production',maxAge:8*36e5,path:'/'});r.json({ok:true})});
app.post('/api/logout',(q,r)=>{r.clearCookie('sid');r.json({ok:true})});
app.get('/api/admin/me',auth,(q,r)=>r.json({csrf:q.s.csrf}));
app.get('/api/admin/bookings',auth,(q,r)=>r.json([...db.bookings].reverse()));
app.post('/api/admin/bookings',auth,(q,r)=>{const b=q.body||{};db.bookings.push({id:crypto.randomUUID(),shop:str(b.shop,80),svc:str(b.svc,80),date:str(b.date,10),time:str(b.time,8),name:str(b.name,80),phone:str(b.phone,20),note:str(b.note,300),status:'confirmed',at:new Date().toISOString()});save();r.json({ok:true})});
app.patch('/api/admin/bookings/:id',auth,(q,r)=>{const b=db.bookings.find(x=>x.id===q.params.id);if(!b)return r.sendStatus(404);if(['new','confirmed','done','cancelled'].includes(q.body?.status))b.status=q.body.status;save();r.json({ok:true})});
app.delete('/api/admin/bookings/:id',auth,(q,r)=>{db.bookings=db.bookings.filter(x=>x.id!==q.params.id);save();r.json({ok:true})});
app.put('/api/admin/content',auth,(q,r)=>{const c=q.body;if(!c||typeof c!=='object'||!['shops','pkgs','plans','team','reviews','gal'].every(k=>Array.isArray(c[k])))return r.status(400).json({error:'invalid'});db.content=c;save();r.json({ok:true})});
app.get('/api/admin/export.csv',auth,(q,r)=>{const e=v=>{v=String(v??'');if(/^[=+\-@]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'};
r.type('text/csv').send('date,time,name,phone,service,shop,status,note\n'+db.bookings.map(b=>[b.date,b.time,b.name,b.phone,b.svc,b.shop,b.status,b.note].map(e).join(',')).join('\n'))});
app.get('/admin',(q,r)=>r.sendFile(path.join(__dirname,'public/admin.html')));
app.use(express.static(path.join(__dirname,'public'),{index:'index.html',extensions:['html']}));
app.listen(PORT,()=>console.log('JAS site on http://localhost:'+PORT));
