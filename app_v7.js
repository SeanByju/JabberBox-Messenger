if(process.env.NODE_ENV !== "production") {
    require('dotenv').config();
}

const express = require('express');
const app = express();
const server = require('http').createServer(app)//creating a http server and passing our express app to it.
const {Server} = require("socket.io");
const io = new Server(server);//initializing socket.io server on same http server
const path = require('path');
const methodOverride = require('method-override'); 
const mongoose = require('mongoose');
const User = require('./models/user');
const Room = require('./models/room');
const FriendRequest = require('./models/friendRequest');
const ejsMate = require('ejs-mate');
const ExpressError = require('./utils/ExpressError');
const catchAsync = require('./utils/catchAsync');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const {isLoggedIn, validateUser} = require('./middleware');
const tokenSecret = process.env.TOKEN_SECRET; 
const jwt = require('jsonwebtoken');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const MongoStore = require('connect-mongo');
const dbURL = process.env.DB_URL || 'mongodb://localhost:27017/jabberBox';
const secret = process.env.SECRET || 'thisshouldbeabettersecret';


mongoose.connect(dbURL)
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
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, '/public')));
app.use(methodOverride('_method'));


//create store
const store = MongoStore.create({
    mongoUrl: dbURL,
    touchAfter: 24 * 60 * 60, //how often you update
    crypto: {
        secret: secret
    }
});

store.on("error", function(e){
    console.log("Session Store Error")
})


//These are the options for our express sessions
const sessionOptions = {
    store,
    name: 'session',
    secret, 
    resave: false, 
    saveUninitialized: true,
    cookie: {
        httpOnly: true, //cookies only available through http not JS
        // secure: true, //this cookie will only work through https
        expires: Date.now() + 1000*60*60*24*7,
        maxAge: 1000*60*60*24*7,
    }
}

//Need to have our session configured before we use passport
app.use(session(sessionOptions));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use(flash());
app.use((req, res, next)=>{
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next()
})
app.use(mongoSanitize());
app.use(helmet({contentSecurityPolicy: false}))



//Generate token at login
function generateAccessToken(userObject) {
    return jwt.sign({userObject}, process.env.TOKEN_SECRET);
}
 

//Welcome page
app.get("/", (req,res) => {
    res.render('welcome');
})

//Register routes
app.get("/register", (req,res) => {
    res.render('register');
})

app.post("/register", validateUser, catchAsync(async(req,res, next) => {
    try{
        const {email, username, password} = req.body;
        const user = new User({email, username});
        const registerdUser = await User.register(user, password);
        req.login(registerdUser, err =>{
            if(err) return next(err);
            req.flash('success', 'Welcome to JabberBox Messenger!');
            res.redirect(`/${user._id}`);
        })
    }catch(e){
        req.flash('error', e.message);
        res.redirect('register');
    }
}))

//Login routes
app.get("/login", (req,res) => {
    res.render('login');
})

app.post('/login', passport.authenticate('local',{failureFlash: true, failureRedirect:'/login'}), catchAsync(async(req, res) => {
    req.flash('success', 'Welcome back! Click "x" to dismiss');
    res.redirect(`/${req.user._id}`);
}))
 
// Logout route
app.get('/logout', function(req, res, next) {
    req.logout(function(err) {
        if (err) { return next(err); }     
        req.flash("success", "GOOD BYE!!");
        res.redirect('/');
    });
});



//User's "home" page, load initial data from database
app.get("/:id", isLoggedIn, catchAsync(async(req,res, next) => {
    res.header('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0'); //prevents back button access after logout
    const {id} = req.params;
    const foundUser = await User.findById(id).populate('friends').populate('pendingFriendRequests');
    if(!foundUser){
        throw new ExpressError('User not found', 404)
    }
    // Create token and add it to User object
    let tokenObject = {
        username: foundUser.username,
        date: Date.now()
    }
    let tokenLatest = generateAccessToken(tokenObject);
    foundUser.token = tokenLatest;
    await foundUser.save();
    res.render('home_v5', {foundUser}); 
}))


app.get("/:id/settings", isLoggedIn, catchAsync(async(req,res, next) => {
    const {id} = req.params;
    const foundUser = await User.findById(id).populate('friends');
    if(!foundUser){
        throw new ExpressError('User not found', 404)
    }
    res.render('settings', {foundUser});
}))

app.delete("/:id/settings/:user", isLoggedIn, catchAsync(async(req,res, next) => {
    const {id, user} = req.params;
    const foundUser = await User.findById(id).populate('friends');
    const deletedFriend = await User.findOne({username: user}).populate('friends');
    let chatRoom = null;
    if(foundUser.username > deletedFriend.username){
        chatRoom = foundUser.username + foundUser._id + deletedFriend.username + deletedFriend._id;
    }else{
        chatRoom = deletedFriend.username + deletedFriend._id + foundUser.username + foundUser._id;
    }

    await foundUser.friends.pull({_id: deletedFriend._id}) 
    await deletedFriend.friends.pull({_id: foundUser._id})
    await foundUser.save();
    await deletedFriend.save();

    const foundRoom = await Room.findOne({name: chatRoom}); 
    
    if(foundRoom){
        await Room.deleteOne({name: chatRoom});
    }
    
    res.redirect(`/${req.user._id}/settings`);
}))


app.all("*", (req, res, next) => {
    next(new ExpressError('Page Not Found', 404))
})

//Error handler
app.use((err, req, res, next) => {
    const {status = 500, message = 'Something went wrong'} = err;
    res.status(status).render('error', {err})

})


//http server (and socket.io server by extension) listens on port 3000 for incoming http ans socket.io requests
const port = process.env.PORT || 3000;
server.listen(port, ()=>{
    console.log(`JabberBoxMessenger listening on port ${port}!`)
})


let onlineUsers = {};
let allSockets = {}; 

// Middleware to validate socket connection
// io.use(async function (socket, next){
//     // console.log("Socket Verification in process")
//     // console.log(socket.handshake.query.username)
//     // console.log(socket.handshake.query.id)
//     // console.log(socket.handshake.auth.token)
//     //Check if user has correct/up-to-date token
//     let foundUser = await User.findOne({token: socket.handshake.auth.token});
//     if(!foundUser){
//         const err = new Error("not authorized");
//         err.data = { content: "Please retry later" };
//         next(err);
//     }
//     //Decode the token for the username to verify that the username passed in the querystring is correct(no tampering)
//     let decodedToken = jwt.verify(socket.handshake.auth.token, tokenSecret);
//     // console.log(decodedToken);
//     if(decodedToken.userObject.username == socket.handshake.query.username){
//         // console.log("VERIFIED!!!")
//         next()
//     }else{
//         const err = new Error("not authorized");
//         err.data = { content: "Please retry later" };
//         next(err);
//     }
// })

// If we get here connection is good to go/ no tampering on client side
io.on('connection', catchAsync(async(clientSocket)=>{
    onlineUsers[clientSocket.handshake.query.username] = clientSocket.id; // add client to global object
    allSockets[clientSocket.handshake.query.username] = clientSocket; // add client socket so we can move them to rooms later
    clientSocket.inAChat = false; 
    clientSocket.activeChatRoom = clientSocket.id; //set this attribute to be the default room on connection
    console.log("All users online:", onlineUsers)

    // Find user in database
    let foundUser = await User.findOne({username: clientSocket.handshake.query.username}).populate('offlineNotifications').populate('pendingFriendRequests');

    // Check if there are any missed messages
    if(foundUser){
        if(foundUser.offlineNotifications.length > 0){
            for(let user of foundUser.offlineNotifications){
                let clientA =  user.username;
                let clientB = clientSocket.handshake.query.username;
                io.to(clientSocket.id).emit('message notification', {clientA, clientB}) // Re-used this emit event from below
            }
            foundUser.offlineNotifications = []; // We've sent all missed notifications, clear array now
            foundUser.save();
        }
        // Check if there are any pending friend requests
        if(foundUser.pendingFriendRequests.length > 0){
            let requests = []
            for(let request of foundUser.pendingFriendRequests){
                let clientA = request.requester;
                requests.push(clientA);
            }
            io.to(clientSocket.id).emit('pending request', requests);
            //PendingFriendRequest will be deleted after the recipient has decided to add or not 
        }
    }
    
    // Check if client has accepted or denied a friend request
    clientSocket.on('request decision', async(data)=>{
        let {clientA = data.sender, clientB = data.recipient, status = data.status} = data;
        // Find existing friendRequest object so we can access it's id for removal later
        let foundRequest = await FriendRequest.findOne({requester: clientB, recipient: clientA});
        // Found user who has the friend request object, will remove either way
        let friendRequestRecipient = await User.findOne({username: clientA}).populate('offlineNotifications').populate('pendingFriendRequests');
        if(status == 2){
            //if accepted find the request sender and make them both friends
            let friendRequestSender = await User.findOne({username: clientB});
            friendRequestSender.friends.push(friendRequestRecipient);
            friendRequestRecipient.friends.push(friendRequestSender);
            await friendRequestSender.save();
            await friendRequestRecipient.save();
            //emit to clientA that they have a new friend (visually add to friend list) and to ClientB if theyre still online
            io.to(allSockets[clientA].activeChatRoom).to(allSockets[clientA].id).emit('new friend', clientB);
            if(onlineUsers[clientB]){
                io.to(allSockets[clientB].activeChatRoom).to(allSockets[clientB].id).emit('new friend', clientA);
            } 
        }

        // If status anything other than 2 remove the friend request object entirely
        await friendRequestRecipient.pendingFriendRequests.pull({_id: foundRequest._id}) //remove the friendRequest object 
        // Delete the friend request object from existence
        await FriendRequest.deleteOne({_id: foundRequest._id});
        await friendRequestRecipient.save();
 
    })

    
    // Client A joins room
    clientSocket.on('join room', async(data)=>{
        let {clientA = data.sender, clientB = data.recipient} = data;
        const senderDoc = await User.findOne({username: clientA}).populate('friends');
        const recipientDoc = await User.findOne({username: clientB}).populate('friends');
        // First check if users are still friends(in event that they have become unfriended)
        let stillFriends = false;
        for(let friend of senderDoc.friends){
            if(friend.username === clientB){
                stillFriends = true;
            }
        }
        if(!stillFriends){
            // Notify the person they cant join the room bc they are no longer friends
            io.to(clientSocket.activeChatRoom).emit('update friends', {clientB})
        }else{
            let chatRoom = null;
            // Logic to create a uniqe chatroom 
            if(senderDoc.username > recipientDoc.username){
                chatRoom = senderDoc.username + senderDoc._id + recipientDoc.username + recipientDoc._id;
            }else{
                chatRoom = recipientDoc.username + recipientDoc._id + senderDoc.username + senderDoc._id;
            }
            
            // Room logic for whether we need to load messages for an existing room or just create a new one
            let msgHistory = null;
            const foundRoom = await Room.findOne({name: chatRoom}); 
            if(foundRoom){
                msgHistory = foundRoom.chat;
            }else{ 
                // New room (first time chatting with Client B)
                let newRoom = new Room({name: chatRoom, chat: ""});
                msgHistory = newRoom.chat; 
                await newRoom.save();
            }

            // Clients joining room logic
            // Add Client A to room
            clientSocket.join(chatRoom); // Add Client A to the existing room
            clientSocket.inAChat = true; // Set Client A's inAChat variable to true
            clientSocket.activeChatRoom = chatRoom; // Setting active chat room Client A is in
            io.to(chatRoom).emit('joined room', {clientA, clientB, msgHistory, chatRoom}) //Client A should join room regardless of Client B

            // Is Client B online? // Revised logic, no more forcing free clients into chats
            if(onlineUsers[clientB]){
                // Check if Client B is already in the chat ClientA is joining 
                if(allSockets[clientB].inAChat && allSockets[clientB].activeChatRoom == chatRoom){
                    // Do nothing both clients are in same room now
                } else{
                    // Client B is online and is either not in chat with you or talking to someone else
                    // So you will just join the room and send Client B a notification
                    io.to(chatRoom).emit('clientB preoccupied', {clientA, clientB, msgHistory})
                }

            } else{
                // Client B is offline, Client A will be sending offline messages to the room they are in
                io.to(chatRoom).emit('clientB offline', {clientA, clientB, msgHistory})
            }
        }
    })

    clientSocket.on('chat message', async(data)=>{
        let {clientA = data.sender, clientB = data.recipient, incomingMsg = data.message, chatRoom = data.room} = data;
        const senderDoc = await User.findOne({username: clientA}).populate('friends');
        //First check if users are still friends
        let stillFriends = false;
        for(let friend of senderDoc.friends){
            if(friend.username === clientB){
                stillFriends = true;
            }
        }

        if(!stillFriends){
            // Notify the person they cant join the room bc they are no longer friends
            io.to(clientSocket.activeChatRoom).emit('update friends', {clientB});
            io.to(clientSocket.activeChatRoom).emit('clear chatwindow');
        }else{

            // Add chat message to database, after you found the room associated with it
            const foundRoom = await Room.findOne({name: clientSocket.activeChatRoom});
            // validate message and sanitize here
            let formattedMsg = `<div id="${clientA}"><p><strong>${clientA}:</strong><br>${incomingMsg}</p></div>`;
            foundRoom.chat+= formattedMsg;
            await foundRoom.save();
        

            // Is Client B online?
            if(onlineUsers[clientB]){ 
                // Is Client B in a different room than Client A?
                if(allSockets[clientB].activeChatRoom !== clientSocket.activeChatRoom){
                    // Emit to the room Client B is in and their default room (so they dont lose notification when they leave their current room)
                    io.to(allSockets[clientB].activeChatRoom).to(allSockets[clientB].id).emit('message notification', {clientA, clientB})//can maybe simplify
                }
            }else {
                // Client B is not online, add client A's user id to client B's offlineNotifcation property
                // Used so that on connection when we can check and send Client B notifcations
                let foundSender = await User.findOne({username: clientA});
                let foundRecipient = await User.findOne({username: clientB});
                foundRecipient.offlineNotifications.push(foundSender) 
                foundRecipient.save();
                // When recipeient logs in we will check to see if array is empty, if not, put icon next to name of sender 
            }
            // Now send message to chatroom
            io.to(chatRoom).emit('chat message', data)
        }
    })

    clientSocket.on('searched user', async(data)=>{
        let {searchedUser = data.searchedUser, clientA = data.sender} = data;
        if(!searchedUser == ""){
            let foundSender = await User.findOne({username: clientSocket.handshake.query.username}).populate('friends', 'username');
            let currentFriendsList = [];
            for(let friend of foundSender.friends){
                currentFriendsList.push(friend.username);
            };
    
            let foundUsers = await User.find({
                username: {
                    $regex: `^${searchedUser}`,
                    $options: 'i'
                }
            }); // Will return array of found usernames similar to what the client searched
            let queryResults = [];
            for(let user of foundUsers){
                // Make sure client can't send a request to themselves and users they are already friends with
                if(user.username !== clientSocket.handshake.query.username && !(currentFriendsList.includes(user.username))){
                    queryResults.push(user.username)//eventually pass id so clicking goes to their profile
                }
            }
            io.to(clientSocket.activeChatRoom).emit('search results', queryResults);
        }
    })

    clientSocket.on('add friend', async(data)=>{
        let {requester = data.sender, recipient = data.recipient} = data;
        // Check if you've already sent a friend request to this person
        let foundRequest = await FriendRequest.findOne({requester: requester, recipient: recipient});
        if(!foundRequest){
            // make a new friendRequest document
            const newRequest = new FriendRequest({requester: requester, recipient: recipient}); // Default status is pending
            await newRequest.save()
            const foundRecipient = await User.findOne({username: recipient}).populate('pendingFriendRequests')
            foundRecipient.pendingFriendRequests.push(newRequest);
            await newRequest.save();
            await foundRecipient.save(); //Saved to user document in event that recipient is offline, 
            // or they dont accept the request right away, they will still be able to view the request
            // later and make a decision then when their home view is loaded.

            // If the recipient is online send them a notifcation
            if(onlineUsers[recipient]){
                let requests = []
                for(let request of foundRecipient.pendingFriendRequests){
                    let requesterName = request.requester;
                    requests.push(requesterName);
                }
                //send notification to active and defaut room of recipient
                io.to(allSockets[recipient].activeChatRoom).to(allSockets[recipient].id).emit('pending request', requests) 
            }   
        } else{
            // Already sent request, maybe emit so we can alert later? TBD
            console.log("sent request already!")
        }
    })

    // When one of the clients exits a chat or switches to a new one, see if the other one is still in the room
    clientSocket.on('leave chat', (data) => {
        let {clientA = data.sender, clientB = data.recipient, exitedRoom = data.room} = data;
        clientSocket.leave(clientSocket.activeChatRoom);
        clientSocket.activeChatRoom = clientSocket.id;// when you leave you are either back in your default room or you joined another, in that case property will immediately be rewritten in join room event
        clientSocket.inAChat = false;
        // Check if room is still occupied, if not then ClientA was the last to leave
        if(allSockets[clientB]){
            if(allSockets[clientB].activeChatRoom == exitedRoom){
                io.to(exitedRoom).emit('user has left room', {clientA}); 
            }
        }
    })

   
    clientSocket.on("disconnecting", () => {
        clientSocket.inAChat = false; 
        clientSocket.activeChatRoom = null;
        // Client is no longer online
        delete onlineUsers[clientSocket.handshake.query.username]; 
        delete allSockets[clientSocket.handshake.query.username];
        console.log(onlineUsers)
        let clientA = clientSocket.handshake.query.username;
        let leftRooms = clientSocket.rooms;
        for(let room of leftRooms){
            io.to(room).emit('user has disconnected', {clientA});
            // console.log(`Rooms ${clientSocket.handshake.query.username} has disconnected from: ${room}`); 
        }
    });
}))


