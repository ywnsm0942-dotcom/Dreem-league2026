import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import multer from "multer";
import path from "path";
import fs from "fs";
import OpenAI from "openai";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, "data.sqlite"));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS news (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 content TEXT NOT NULL,
 image TEXT,
 category TEXT DEFAULT 'عام',
 author_id INTEGER,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS matches (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 home TEXT NOT NULL,
 away TEXT NOT NULL,
 home_score INTEGER,
 away_score INTEGER,
 kickoff TEXT NOT NULL,
 league TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'upcoming'
);
CREATE TABLE IF NOT EXISTS leagues (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 country TEXT,
 icon TEXT
);
`);

fs.mkdirSync(path.join(__dirname, "uploads"), {recursive:true});

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
 secret: process.env.SESSION_SECRET || "dev-only-change-me",
 resave:false, saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:1000*60*60*24*7}
}));
app.use("/uploads", express.static(path.join(__dirname,"uploads")));
app.use(express.static(path.join(__dirname,"public")));

const upload = multer({
 storage: multer.diskStorage({
  destination: (_,__,cb)=>cb(null,path.join(__dirname,"uploads")),
  filename: (_,file,cb)=>{
   const ext=path.extname(file.originalname).toLowerCase();
   cb(null,`${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
 }),
 limits:{fileSize:5*1024*1024},
 fileFilter:(_,file,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});

function seed(){
 const adminEmail=process.env.ADMIN_EMAIL || "mohamed44@gamil.com";
 const adminPass=process.env.ADMIN_PASSWORD || "wert12345";
 const exists=db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
 if(!exists){
   const hash=bcrypt.hashSync(adminPass,12);
   db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')").run("محمد يونس",adminEmail,hash);
 }
 if(db.prepare("SELECT COUNT(*) c FROM leagues").get().c===0){
   const add=db.prepare("INSERT INTO leagues(name,country,icon) VALUES(?,?,?)");
   [["الدوري المصري","مصر","🇪🇬"],["الدوري الإنجليزي","إنجلترا","🏴"],["الدوري الإسباني","إسبانيا","🇪🇸"],["دوري أبطال أوروبا","أوروبا","⭐"]].forEach(x=>add.run(...x));
 }
 if(db.prepare("SELECT COUNT(*) c FROM matches").get().c===0){
   const add=db.prepare("INSERT INTO matches(home,away,kickoff,league,status) VALUES(?,?,?,?,?)");
   add.run("الأهلي","الزمالك","2026-08-15T20:00","الدوري المصري","upcoming");
   add.run("ليفربول","أرسنال","2026-08-15T22:00","الدوري الإنجليزي","upcoming");
   add.run("ريال مدريد","برشلونة","2026-08-16T21:00","الدوري الإسباني","upcoming");
 }
}
seed();

function requireAuth(req,res,next){
 if(!req.session.user) return res.status(401).json({error:"يجب تسجيل الدخول"});
 next();
}
function requireAdmin(req,res,next){
 if(!req.session.user || req.session.user.role!=="admin") return res.status(403).json({error:"صلاحيات الأدمن مطلوبة"});
 next();
}

app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.post("/api/register", async (req,res)=>{
 const {name,email,password}=req.body||{};
 if(!name||!email||!password||password.length<6) return res.status(400).json({error:"الاسم والبريد وكلمة المرور (6 أحرف على الأقل) مطلوبة"});
 const clean=email.trim().toLowerCase();
 if(db.prepare("SELECT id FROM users WHERE email=?").get(clean)) return res.status(409).json({error:"البريد مسجل بالفعل"});
 const hash=await bcrypt.hash(password,12);
 const result=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),clean,hash);
 const user={id:result.lastInsertRowid,name:name.trim(),email:clean,role:"user"};
 req.session.user=user;
 res.json({user});
});

app.post("/api/login", async (req,res)=>{
 const {email,password}=req.body||{};
 const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
 if(!u || !(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"البريد أو كلمة المرور غير صحيحة"});
 req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};
 res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/news",(req,res)=>{
 const rows=db.prepare(`SELECT n.id,n.title,n.content,n.image,n.category,n.created_at,u.name author
 FROM news n LEFT JOIN users u ON u.id=n.author_id ORDER BY n.id DESC`).all();
 res.json(rows);
});
app.post("/api/news",requireAdmin,upload.single("image"),(req,res)=>{
 const {title,content,category="عام"}=req.body;
 if(!title||!content) return res.status(400).json({error:"العنوان والمحتوى مطلوبان"});
 const image=req.file?`/uploads/${req.file.filename}`:"";
 const r=db.prepare("INSERT INTO news(title,content,image,category,author_id) VALUES(?,?,?,?,?)").run(title,content, image,category,req.session.user.id);
 res.json(db.prepare("SELECT * FROM news WHERE id=?").get(r.lastInsertRowid));
});
app.delete("/api/news/:id",requireAdmin,(req,res)=>{
 const row=db.prepare("SELECT image FROM news WHERE id=?").get(req.params.id);
 if(row?.image) {const p=path.join(__dirname,row.image.replace("/uploads/","uploads/")); if(fs.existsSync(p)) fs.unlinkSync(p);}
 db.prepare("DELETE FROM news WHERE id=?").run(req.params.id);
 res.json({ok:true});
});

app.get("/api/matches",(req,res)=>res.json(db.prepare("SELECT * FROM matches ORDER BY kickoff").all()));
app.get("/api/leagues",(req,res)=>res.json(db.prepare("SELECT * FROM leagues ORDER BY id").all()));

app.post("/api/ai",requireAuth,async(req,res)=>{
 const prompt=String(req.body?.prompt||"").trim();
 if(!prompt) return res.status(400).json({error:"اكتب طلبك"});
 if(!process.env.OPENAI_API_KEY) return res.json({answer:"مساعد موسم الذكي جاهز، لكن لم يتم وضع OPENAI_API_KEY في إعدادات الاستضافة بعد. أضف المفتاح في متغيرات البيئة لتفعيل الذكاء الاصطناعي الحقيقي."});
 try{
  const client=new OpenAI({apiKey:process.env.OPENAI_API_KEY});
  const response=await client.responses.create({
   model:process.env.OPENAI_MODEL||"gpt-5-mini",
   input:`أنت مساعد رياضي داخل تطبيق موسم دريم ليج. أجب بالعربية المصرية باختصار وبدون اختلاق نتائج أو أخبار مؤكدة. طلب المستخدم: ${prompt}`
  });
  res.json({answer:response.output_text});
 }catch(e){res.status(500).json({error:"تعذر تشغيل المساعد حاليًا"})}
});

app.get("*",(req,res)=>{
 if(req.path.startsWith("/api/")) return res.status(404).json({error:"Not found"});
 res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(PORT,()=>console.log(`Mawsem Dream League running on http://localhost:${PORT}`));