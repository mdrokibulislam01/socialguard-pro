const express=require('express'),helmet=require('helmet'),cookie=require('cookie-parser'),jwt=require('jsonwebtoken'),
bcrypt=require('bcryptjs'),multer=require('multer'),Database=require('better-sqlite3'),rate=require('express-rate-limit'),
path=require('path'),crypto=require('crypto'),fs=require('fs');
const SECRET=process.env.JWT_SECRET; if(!SECRET||SECRET.length<24){console.error('Set JWT_SECRET (24+ chars)');process.exit(1)}
const db=new Database('data.db');db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,hash TEXT,name TEXT);
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,user_id INT,platform TEXT,url TEXT,category TEXT,relation TEXT,description TEXT,
 original_url TEXT,owner_declared INT DEFAULT 0,status TEXT DEFAULT 'investigation_started',reference TEXT,outcome_note TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY,case_id INT,kind TEXT,value TEXT,note TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,case_id INT,text TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);`);
const app=express();app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["https://fonts.gstatic.com"],scriptSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:"]}}}));
app.use(express.json({limit:'100kb'}),cookie());app.use(express.static('public'));
app.use('/api/auth',rate({windowMs:15*60*1000,max:30}));
const CATS={fake_identity:'Fake identity',impersonation:'Impersonation',harassment:'Harassment and bullying',fraud:'Fraud and scams',stolen_photos:'Stolen personal photographs',unauthorized_content:'Unauthorized content usage',copyright:'Copyright infringement',threats:'Threatening or abusive behavior'};
const STATUS=['investigation_started','evidence_collected','complaint_prepared','complaint_submitted','under_review','action_taken','closed'];
const HOSTS={facebook:/(^|\.)(facebook\.com|fb\.com|fb\.watch)$/,instagram:/(^|\.)instagram\.com$/,tiktok:/(^|\.)tiktok\.com$/};
function detect(u){try{const x=new URL(u);if(!/^https?:$/.test(x.protocol))return null;for(const[k,r]of Object.entries(HOSTS))if(r.test(x.hostname))return k}catch{}return null}
const FORMS={facebook:{report:'https://www.facebook.com/help/174210519303259',copyright:'https://www.facebook.com/help/1020633957973118'},
instagram:{report:'https://help.instagram.com/370054663112398',copyright:'https://help.instagram.com/contact/552695131608132'},
tiktok:{report:'https://support.tiktok.com/en/safety-hc/report-a-problem',copyright:'https://www.tiktok.com/legal/report/Copyright'}};
const auth=(q,s,n)=>{try{q.user=jwt.verify(q.cookies.sg,SECRET);n()}catch{s.status(401).json({error:'Please sign in'})}};
const setTok=(s,u)=>s.cookie('sg',jwt.sign({id:u.id,name:u.name},SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production'});
const ev=(id,t)=>db.prepare('INSERT INTO events(case_id,text)VALUES(?,?)').run(id,t);
app.post('/api/auth/register',(q,s)=>{const{email,password,name}=q.body;if(!/^\S+@\S+\.\S+$/.test(email||'')||(password||'').length<10)return s.status(400).json({error:'Valid email and a 10+ character password required'});
 try{const r=db.prepare('INSERT INTO users(email,hash,name)VALUES(?,?,?)').run(email.toLowerCase(),bcrypt.hashSync(password,12),(name||'').slice(0,80));setTok(s,{id:r.lastInsertRowid,name});s.json({ok:1})}catch{s.status(409).json({error:'Email already registered'})}});
app.post('/api/auth/login',(q,s)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get((q.body.email||'').toLowerCase());
 if(!u||!bcrypt.compareSync(q.body.password||'',u.hash))return s.status(401).json({error:'Wrong email or password'});setTok(s,u);s.json({ok:1,name:u.name})});
app.post('/api/auth/logout',(q,s)=>{s.clearCookie('sg');s.json({ok:1})});
app.get('/api/meta',auth,(q,s)=>s.json({CATS,STATUS}));
app.get('/api/stats',auth,(q,s)=>{const u=q.user.id,c=x=>db.prepare(x).get(u).n;
 s.json({total:c('SELECT COUNT(*)n FROM cases WHERE user_id=?'),prepared:c("SELECT COUNT(*)n FROM cases WHERE user_id=? AND status!='investigation_started' AND status!='evidence_collected'"),
 submitted:c("SELECT COUNT(*)n FROM cases WHERE user_id=? AND status IN('complaint_submitted','under_review','action_taken','closed')"),
 resolved:c("SELECT COUNT(*)n FROM cases WHERE user_id=? AND status IN('action_taken','closed')"),
 platforms:db.prepare('SELECT platform,COUNT(*)n FROM cases WHERE user_id=? GROUP BY platform').all(u),
 recent:db.prepare('SELECT id,platform,url,category,status,created FROM cases WHERE user_id=? ORDER BY id DESC LIMIT 6').all(u)})});
app.get('/api/cases',auth,(q,s)=>s.json(db.prepare('SELECT * FROM cases WHERE user_id=? ORDER BY id DESC').all(q.user.id)));
app.post('/api/cases',auth,(q,s)=>{const b=q.body,p=detect(b.url);
 if(!p)return s.status(400).json({error:'Paste a Facebook, Instagram or TikTok URL'});
 if(!CATS[b.category])return s.status(400).json({error:'Choose a violation category'});
 if(!b.attest)return s.status(400).json({error:'You must confirm the report is truthful and made in good faith'});
 if(!(b.description||'').trim())return s.status(400).json({error:'Describe what happened'});
 if(b.category==='copyright'&&(!b.original_url||!b.owner_declared))return s.status(400).json({error:'Copyright cases need the original content URL and an ownership declaration'});
 if(db.prepare("SELECT COUNT(*)n FROM cases WHERE user_id=? AND created>datetime('now','-1 day')").get(q.user.id).n>=5)return s.status(429).json({error:'Daily case limit reached (5). Each case needs genuine evidence.'});
 if(db.prepare('SELECT id FROM cases WHERE user_id=? AND url=?').get(q.user.id,b.url))return s.status(409).json({error:'You already have a case for this profile'});
 const r=db.prepare('INSERT INTO cases(user_id,platform,url,category,relation,description,original_url,owner_declared)VALUES(?,?,?,?,?,?,?,?)')
 .run(q.user.id,p,b.url.slice(0,500),b.category,b.relation||'witness',b.description.slice(0,4000),(b.original_url||'').slice(0,500),b.owner_declared?1:0);
 ev(r.lastInsertRowid,`Case opened for ${p} profile (user-reported: ${CATS[b.category]}). Profile contents have not been verified by this system.`);s.json({id:r.lastInsertRowid})});
const mine=(q,s,n)=>{const c=db.prepare('SELECT * FROM cases WHERE id=? AND user_id=?').get(q.params.id,q.user.id);if(!c)return s.status(404).json({error:'Not found'});q.c=c;n()};
app.get('/api/cases/:id',auth,mine,(q,s)=>s.json({case:q.c,forms:FORMS[q.c.platform],evidence:db.prepare('SELECT * FROM evidence WHERE case_id=? ORDER BY id').all(q.c.id),events:db.prepare('SELECT * FROM events WHERE case_id=? ORDER BY id').all(q.c.id)}));
const up=multer({storage:multer.diskStorage({destination:'uploads',filename:(q,f,cb)=>cb(null,crypto.randomUUID()+({'image/png':'.png','image/jpeg':'.jpg','image/webp':'.webp','application/pdf':'.pdf'}[f.mimetype]||''))}),
 limits:{fileSize:8e6},fileFilter:(q,f,cb)=>cb(null,['image/png','image/jpeg','image/webp','application/pdf'].includes(f.mimetype))});
const advance=(c,to)=>{if(STATUS.indexOf(to)>STATUS.indexOf(c.status))db.prepare('UPDATE cases SET status=? WHERE id=?').run(to,c.id)};
app.post('/api/cases/:id/evidence',auth,mine,up.single('file'),(q,s)=>{
 const kind=q.file?'file':(q.body.kind||'url'),val=q.file?q.file.filename:(q.body.value||'').slice(0,500);if(!val)return s.status(400).json({error:'Nothing to add (images/PDF up to 8 MB)'});
 db.prepare('INSERT INTO evidence(case_id,kind,value,note)VALUES(?,?,?,?)').run(q.c.id,kind,val,(q.body.note||'').slice(0,500));ev(q.c.id,`Evidence added (${kind})`);advance(q.c,'evidence_collected');s.json({ok:1})});
app.get('/api/files/:name',auth,(q,s)=>{const n=path.basename(q.params.name);const e=db.prepare('SELECT c.user_id FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.value=?').get(n);
 if(!e||e.user_id!==q.user.id)return s.sendStatus(404);s.sendFile(path.resolve('uploads',n))});
app.post('/api/cases/:id/status',auth,mine,(q,s)=>{const{status,reference,note}=q.body;if(!STATUS.includes(status))return s.sendStatus(400);
 if(status==='complaint_submitted'&&!q.body.confirm)return s.status(400).json({error:'Confirm you submitted this on the official platform'});
 if(status==='action_taken'&&!(note||'').trim())return s.status(400).json({error:'Paste the platform notification as proof of the outcome'});
 db.prepare('UPDATE cases SET status=?,reference=COALESCE(?,reference),outcome_note=COALESCE(?,outcome_note) WHERE id=?').run(status,reference||null,note||null,q.c.id);
 ev(q.c.id,`Status set to ${status} by user${reference?` (ref ${reference})`:''}${status==='action_taken'?' - outcome recorded from user-supplied platform notice':''}`);s.json({ok:1})});
const POL={facebook:'Facebook Community Standards',instagram:'Instagram Community Guidelines',tiktok:'TikTok Community Guidelines'};
const REL={self:['the person being impersonated or targeted','যার পরিচয়/ছবি ব্যবহার করা হয়েছে সেই ব্যক্তি'],rep:['an authorized representative of the affected party','ক্ষতিগ্রস্ত ব্যক্তির অনুমোদিত প্রতিনিধি'],witness:['a user who encountered this account','একজন ব্যবহারকারী যিনি এই অ্যাকাউন্টটি দেখেছেন']};
const BN={fake_identity:'ভুয়া পরিচয়',impersonation:'ছদ্মবেশ ধারণ',harassment:'হয়রানি ও বুলিং',fraud:'প্রতারণা',stolen_photos:'ব্যক্তিগত ছবি চুরি',unauthorized_content:'অনুমতি ছাড়া কনটেন্ট ব্যবহার',copyright:'কপিরাইট লঙ্ঘন',threats:'হুমকি বা আপত্তিকর আচরণ'};
app.get('/api/cases/:id/complaint',auth,mine,(q,s)=>{const c=q.c,n=db.prepare('SELECT COUNT(*)n FROM evidence WHERE case_id=?').get(c.id).n,
 urls=db.prepare("SELECT value,note FROM evidence WHERE case_id=? AND kind!='file'").all(c.id).map(e=>`- ${e.value}${e.note?' ('+e.note+')':''}`).join('\n')||'- (none added)';
 const r=REL[c.relation]||REL.witness,cp=c.category==='copyright';
 const en=cp?`Subject: Copyright infringement report - ${c.url}

I am writing to report copyright infringement on ${c.platform}.

Original work (owned by me or a party I am authorized to represent): ${c.original_url}
Infringing content/profile: ${c.url}

Details: ${c.description}

Supporting evidence (${n} file(s) attached, plus links):
${urls}

I have a good-faith belief that this use is not authorized by the copyright owner, its agent, or the law. I declare that the information in this notice is accurate and that I am the copyright owner or authorized to act on the owner's behalf.

Name: [YOUR FULL LEGAL NAME]
Contact: [YOUR EMAIL]
Signature: [YOUR SIGNATURE]`
 :`Subject: Report of ${CATS[c.category].toLowerCase()} - ${c.url}

Hello ${c.platform} Support,

I am ${r[0]}. I am reporting the account at ${c.url} for ${CATS[c.category].toLowerCase()}, which I believe violates the ${POL[c.platform]}.

What happened: ${c.description}

Evidence (${n} file(s) attached, plus links):
${urls}

I have not been able to verify any information beyond what is described above, and I ask your team to review the account against your policies. Please contact me if you need more information.

Thank you,
[YOUR NAME]`;
 const bn=cp?`বিষয়: কপিরাইট লঙ্ঘনের অভিযোগ - ${c.url}

আমি ${c.platform}-এ কপিরাইট লঙ্ঘনের বিষয়ে অভিযোগ জানাচ্ছি।

মূল কনটেন্ট (আমার বা আমার অনুমোদিত পক্ষের): ${c.original_url}
লঙ্ঘনকারী কনটেন্ট/প্রোফাইল: ${c.url}

বিবরণ: ${c.description}

প্রমাণ (${n}টি ফাইল সংযুক্ত এবং লিংক):
${urls}

আমি সরল বিশ্বাসে মনে করি এই ব্যবহারে কপিরাইট মালিকের অনুমতি নেই। আমি ঘোষণা করছি এই তথ্য সঠিক এবং আমি কপিরাইট মালিক অথবা তাঁর পক্ষে কাজ করার অনুমোদিত ব্যক্তি।

নাম: [আপনার পূর্ণ নাম]
যোগাযোগ: [আপনার ইমেইল]`
 :`বিষয়: ${BN[c.category]} সংক্রান্ত অভিযোগ - ${c.url}

${c.platform} সাপোর্ট টিম,

আমি ${r[1]}। আমি ${c.url} অ্যাকাউন্টটির বিরুদ্ধে ${BN[c.category]}-এর অভিযোগ জানাচ্ছি, যা ${POL[c.platform]} লঙ্ঘন করে বলে আমি মনে করি।

ঘটনার বিবরণ: ${c.description}

প্রমাণ (${n}টি ফাইল সংযুক্ত এবং লিংক):
${urls}

উপরে উল্লিখিত তথ্যের বাইরে আমি অন্য কিছু যাচাই করতে পারিনি। অনুগ্রহ করে আপনাদের নীতিমালা অনুযায়ী অ্যাকাউন্টটি পর্যালোচনা করুন।

ধন্যবাদান্তে,
[আপনার নাম]`;
 advance(c,'complaint_prepared');s.json({en,bn,form:FORMS[c.platform][cp?'copyright':'report']})});
app.listen(process.env.PORT||3000,()=>console.log('SocialGuard Pro running'));
