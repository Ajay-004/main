const mongoose = require('mongoose');

const ChatSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    history: { type: Array, default: [] }
}, { timestamps: true });

module.exports = mongoose.model('Chat', ChatSchema);
