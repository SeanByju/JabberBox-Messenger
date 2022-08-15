const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        required: [true, "Must have a username!"]
    },
    email: {
        type: String,
        required: [true, "Email required!"]
    },
    friends: [
        {
            type: Schema.Types.ObjectId,
            ref: 'User'
        }
    ] 
})

const User = mongoose.model('User', userSchema);

module.exports = User;