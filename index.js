const express=require('express');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcrypt');
const Redis=require('redis');
const winston=require('winston');
require('dotenv').config();
const {connection}=require('./db');
const mongoose=require('mongoose')
const {userModel}=require('./models/userModel');
const app=express();
app.use(express.json());

const redisClient=Redis.createClient(process.env.Redis_Url);
// redisClient.on('error')

const logger=winston.createLogger({
    level:'error',
    transports:[
        new winston.transports.Console(),
        new winston.transports.MonngoDB({
            level:'error',
            db:process.env.Mongo_Url,            
        })
    ]
})


const authentication=async (req,res,next)=>{
    const token=req.headers.authorization?.split(' ')[1];
    if(!token){
        return res.status(401).json({error:'No Token'});
    }
    try{
        const docoded=jwt.verify(token,process.env.Jwt_Secret)
        const blaclisted=await redisClient.get(decoded)
        if(blacklisted){
            return res.status(401).json({error:'Token is Blaclisted'})
        }
        req.user=decoded;
        next()
    }
    catch(err){
        res.status(401).json({error:'Invalid Token'});
    }
}

app.post('/register',async(req,res)=>{
    try{
        const {email,password}=req.body;
        const hashedPassword=await bcrypt.hash(password,6);
        const user=new userModel({email,password:hashedPassword});
        await user.save();
        res.status(201).json({message:'User Registered'});
    }
    catch(err){
        res.status(500).json({error:err.message});
    }
})


app.post('/login',async(req,res)=>{
    try{
        const {email,password}=req.body;
        const user=await userModel.findOne({email});
        if(!user){
            return res.status(401).json({error:'Invalid credentials'});
        }
        const match=await bcrypt.compare(password,user.password);
        if(!match){
            return res.status(401).json({error:'Invalid credentials'});
        }

        const token=jwt.sign(
            {sub:user.id},
            process.env.Jwt_Secret
        )

        res.json(token);
    }
    catch(err){
        logger.error(err);
        res.status(500).json({error:'server error'})
    }
})

app.post('/logout',authentication,async(req,res)=>{
    try{
        const decoded=jwt.decode(req.headers.authorization.split(' ')[1]);
        await redisClient.set(decoded,'blacklisted','EX',6*60*60);
        res.send("User logged out");
    }
    catch(err){
        logger.error(err);
        res.send(err);
    }
})

