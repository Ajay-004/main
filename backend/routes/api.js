const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const multer = require('multer');
const mongoose = require('mongoose');
const cors = require('cors');
const OpenAI = require('openai');
require('dotenv').config();

// --- MODELS ---
const User = require('../models/User');
const Chat = require('../models/chat');

// --- INITIALIZATION ---
const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Initialize the client for an OpenAI-compatible service (like OpenRouter)
const openrouter = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY,
});

// --- MIDDLEWARE ---
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied.' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid.' });
    }
};

// =============== USER AUTHENTICATION ROUTES ===============
router.post('/signup', async (req, res) => {
    const { username, email, phone, password, state } = req.body;
    try {
        if (!username || !email || !phone || !password || !state) {
            return res.status(400).json({ message: 'Please enter all fields.' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, phone, password: hashedPassword, state });
        await newUser.save();
        res.status(201).json({ message: 'Account created successfully!' });
    } catch (err) {
        console.error("Signup Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error("Profile Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});


// =============== CHATBOT ROUTE ===============
router.post('/chat', authMiddleware, upload.single('image'), async (req, res) => {
    const { message, chatId, language } = req.body;

    if (!message && !req.file) {
        return res.status(400).json({ message: 'Message or image is required.' });
    }

    try {
        let currentChat;
        if (chatId) {
            currentChat = await Chat.findOne({ _id: chatId, userId: req.user.id });
        } else {
            const title = message ? message.substring(0, 30) + '...' : "New Image Chat";
            currentChat = new Chat({ userId: req.user.id, title, history: [] });
        }
        if (!currentChat) return res.status(404).json({ message: "Chat not found" });
        
        // Handle message for a text-only model like Gemma
        const userMessageContent = req.file 
            ? `${message || ''} (An image was uploaded, but I am a text-only AI and cannot see it. Please describe the image if you want me to know what it is.)`.trim()
            : message;
            
        currentChat.history.push({ role: 'user', parts: [{ text: userMessageContent }] });

        // System prompt for the AI model
        let systemInstructionText = "You are FarmWise Bot, an expert agricultural assistant. Your primary function is to help with farming questions. Be concise and helpful.";
        const languageMap = { 'ta': 'Tamil', 'ml': 'Malayalam' };
        if (language && languageMap[language]) {
            systemInstructionText += ` IMPORTANT: You must provide your entire response ONLY in the ${languageMap[language]} language.`;
        }

        // Transform history into the format required by the OpenAI-compatible API
        const messagesForAPI = currentChat.history.map(msg => ({
            role: msg.role === 'model' ? 'assistant' : 'user',
            content: msg.parts.map(part => part.text).join(' ')
        }));

        messagesForAPI.unshift({ role: 'system', content: systemInstructionText });

        // API call is now made using the OpenAI library
        const completion = await openrouter.chat.completions.create({
            model: "google/gemma-3-27b-it", // The specified Gemma model
            messages: messagesForAPI,
        });

        const botReplyText = completion.choices[0].message.content;
        if (!botReplyText) {
            console.error("Invalid API Response:", completion);
            return res.status(500).json({ message: 'AI model returned an invalid response.' });
        }
        
        const botMessage = { role: 'model', parts: [{ text: botReplyText }] };
        currentChat.history.push(botMessage);
        await currentChat.save();

        res.json({ reply: botReplyText, newChatId: !chatId ? currentChat.id : undefined });

    } catch (error) {
        console.error("API Error:", error);
        res.status(500).json({ message: 'Failed to get response from AI model.' });
    }
});


// =============== CHAT HISTORY ROUTES ===============
router.get('/chats', authMiddleware, async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(chats);
    } catch (err) {
        console.error("Get Chats Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
        const chat = await Chat.findOne({ _id: req.params.chatId, userId: req.user.id });
        if (!chat) {
            return res.status(404).json({ message: 'Chat not found.' });
        }
        res.json(chat.history);
    } catch (err) {
        console.error("Get Chat History Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.delete('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
        const { chatId } = req.params;
        const chat = await Chat.findOneAndDelete({ _id: chatId, userId: req.user.id });
        if (!chat) {
            return res.status(404).json({ message: 'Chat not found or you do not have permission to delete it.' });
        }
        res.json({ message: 'Chat deleted successfully.' });
    } catch (err) {
        console.error("Delete Chat Error:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

// =============== WEATHER ROUTE ===============
router.get('/weather/forecast', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const location = user.state || 'Coimbatore'; // Default location
        const apiKey = process.env.WEATHER_API_KEY;

        const geoUrl = `http://api.openweathermap.org/geo/1.0/direct?q=${location},IN&limit=1&appid=${apiKey}`;
        const geoResponse = await axios.get(geoUrl);
        if (!geoResponse.data || geoResponse.data.length === 0) {
            return res.status(404).json({ message: "Location not found." });
        }
        const { lat, lon } = geoResponse.data[0];

        const forecastUrl = `https://api.openweathermap.org/data/3.0/onecall?lat=${lat}&lon=${lon}&exclude=minutely,alerts&appid=${apiKey}&units=metric`;
        const forecastResponse = await axios.get(forecastUrl);
        
        res.json(forecastResponse.data);
    } catch (err) {
        console.error("Weather Forecast Error:", err.message);
        res.status(500).json({ message: "Could not fetch weather forecast." });
    }
});

module.exports = router;