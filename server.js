const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./gtps.db');
db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)`);
db.run(`CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, itemId INTEGER, dropChance REAL, xpMultiplier REAL, gemMultiplier REAL)`);

// REGISTER & login (Dasar)
app.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username,password,role) VALUES(?,?,?)`, [username, hashed, role], function(err){
    if(err) return res.status(400).json({error: err.message});
    res.json({id:this.lastID,username,role});
  });
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (e,u)=>{
    if(!u || !bcrypt.compareSync(password,u.password)) return res.status(401).json({message:'Invalid'});
    const token = jwt.sign({id:u.id,username:u.username,role:u.role}, 'secret');
    res.json({token,role: u.role});
  });
});

// Middleware auth
function auth(r){return (req,res,next)=>{
  const t = req.headers.authorization?.split(' ')[1];
  if(!t) return res.status(403).json({message:'No token'});
  jwt.verify(t,'secret',(err,d)=>{
    if(err) return res.status(401).json({message:'Invalid'});
    req.user = d;
    if(r && d.role!=='The King') return res.status(403).json({message:'Insufficient'});
    next();
  });
};}

// CRUD item
app.get('/items', auth(), (req,res)=>{
  db.all('SELECT * FROM items', (e,rows)=>res.json(rows));
});
app.post('/items', auth('The King'), (req,res)=>{
  const {name,itemId,dropChance,xpMultiplier,gemMultiplier} = req.body;
  db.run(`INSERT INTO items (name,itemId,dropChance,xpMultiplier,gemMultiplier) VALUES(?,?,?,?,?)`, [name,itemId,dropChance,xpMultiplier,gemMultiplier], function(err){
    if(err) return res.status(500).json({error:err.message});
    res.json({id:this.lastID});
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT,()=>console.log(`Server @ ${PORT}`));
