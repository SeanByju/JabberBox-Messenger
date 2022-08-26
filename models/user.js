const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },

    friends: [
        {
            type: Schema.Types.ObjectId,
            ref: 'User'
        }
    ], 
    // Not Used
    // rooms: [
    //     {
    //         type: Schema.Types.ObjectId,
    //         ref: 'Room'
    //     }
    // ],

    offlineNotifications: [
        {
            type: Schema.Types.ObjectId,
            ref: 'User'
        }
    ],

    pendingFriendRequests: [
        {
            type: Schema.Types.ObjectId,
            ref: 'FriendRequest'
        }
    ],

    token: {
        type: String
    }
})

userSchema.plugin(passportLocalMongoose); //will add on username and password fields to our schema

const User = mongoose.model('User', userSchema);

module.exports = User;