const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const friendRequestSchema = new Schema({
    requester: {
        type: String,
    },

    recipient: {
        type: String,
    },

    status: 
        {
            type: Number,
            default: 1 //1: pending, 2: accepted, 3: rejected
        }
    , 
})

const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

module.exports = FriendRequest;