const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    state: { type: String, required: true },
    chatHistory: { type: Array, default: [] }
});

module.exports = mongoose.model('User', UserSchema);
