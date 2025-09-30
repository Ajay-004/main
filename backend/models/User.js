const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true // Good practice to remove whitespace
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true // Good practice to remove whitespace
        },
        phone: {
            type: String,
            required: true
        },
        password: {
            type: String,
            required: true
        },
        state: {
            type: String,
            required: true
        }
    },
    {
        // Automatically adds `createdAt` and `updatedAt` fields
        timestamps: true 
    }
);

module.exports = mongoose.model('User', UserSchema);
