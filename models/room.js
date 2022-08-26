const mongoose = require('mongoose');
const Schema = mongoose.Schema;

//old schema
// const roomSchema = new Schema({
//     name: {
//         type: String
//     },

//     chat: {
//         type: Schema.Types.ObjectId,
//         ref: 'Messages'
//     }
// })

const roomSchema = new Schema({
    name: {
        type: String
    },

    chat: {
        type: String
    }
})

const Room = mongoose.model('Room', roomSchema);

module.exports = Room;