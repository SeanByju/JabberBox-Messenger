const express = require('express');
const app = express();
const path = require('path');
const socket = require('socket.io')//requiring socket.io library
const mongoose = require('mongoose');
const User = require('./models/user')
const ejsMate = require('ejs-mate');



mongoose.connect('mongodb://localhost:27017/jabberBox')
    .then(()=> {
        console.log("MongoDB Connection Opened!");
    })
    .catch((error) =>{
        console.log("Oh no, database connection error!")
        console.log(error);
    })


    
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '/views'));
app.engine('ejs', ejsMate);
app.use(express.urlencoded({extended: true}));
app.use(express.json());


app.get("/jabberbox", (req,res) => {
    res.render('welcome');
})

app.get("/jabberbox/register", (req,res) => {
    res.render('register');
})

app.post("/jabberbox/register", async(req,res) => {
    const newUser = new User(req.body);
    await newUser.save();
    res.redirect(`/jabberbox/${newUser._id}`);
})

app.get("/jabberbox/login", (req,res) => {
    res.render('login');
})

app.post("/jabberbox/login", async(req,res) => {
    const {username} = req.body;
    const foundUser = await User.findOne({username: username})
    res.redirect(`/jabberbox/${foundUser._id}`);
})

//user's "home" page
app.get("/jabberbox/:id", async(req,res) => {
    const {id} = req.params;
    const foundUser = await User.findById(id).populate('friends');
    res.render('home', {foundUser});
})

app.get("/jabberbox/:id/search", (req,res) => {
    const {id} = req.params;
    res.render('search', {id});
})

app.post("/jabberbox/:id/search", async(req,res) => {
    const {id} = req.params;
    const {username} = req.body;
    const currentUser = await User.findById(id);
    const foundFriend = await User.findOne({username: username});
    currentUser.friends.push(foundFriend); //adding found friend to the current user's friend list 
    foundFriend.friends.push(currentUser); // adding current friend to the found friends friend list
    await currentUser.save();
    await foundFriend.save();
    res.redirect(`/jabberbox/${currentUser._id}`)

})

//app.listen returns a server instance that you can attach socket.io on to
const serverInstance = app.listen(3000, ()=>{
    console.log("JabberBoxMessenger listening on port 3000!")
})



const io = socket(serverInstance);//invoke socket method and pass in the sever we want to work with
//socket.io will be sitting around on the server waiting for a client to make a connetion


//listening for connections
//clientSocket refers to the individual clients that have connected to us
let allUsers = {};
io.on('connection', (clientSocket)=>{
    console.log("Socket connection established!", clientSocket.id);
    allUsers


    clientSocket.on('chat message', (data)=>{
        data.recipient
        console.log(data)
        io.sockets.emit('chat message', data); //emmitting to ALL sockets!
    })

    clientSocket.on('typing', (data) =>{
        clientSocket.broadcast.emit('typing', data);
    })
})
