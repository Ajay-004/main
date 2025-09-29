const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const multer = require('multer');
const OpenAI = require('openai');
require('dotenv').config();

// --- MODELS ---
const User = require('../models/User');
const Chat = require('../models/chat');

// --- INITIALIZATION ---
const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() }); // Use memoryStorage to handle file buffer

// Initialize the client for the OpenAI-compatible OpenRouter service
const openrouter = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY,
});

// --- AUTHENTICATION MIDDLEWARE ---
// This function protects routes by verifying the user's JWT
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

// =============== API ROOT (FOR TESTING) ===============
router.get('/', (req, res) => {
    res.json({ message: 'FarmWise API is running correctly.' });
});

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

// =============== CHATBOT ROUTE (WITH IMAGE DIAGNOSIS) ===============
router.post('/chat', authMiddleware, upload.single('image'), async (req, res) => {
    const { message, chatId, language } = req.body;
    const imageFile = req.file;

    if (!message && !imageFile) {
        return res.status(400).json({ message: 'Message or image is required.' });
    }

    try {
        let currentChat;
        if (chatId) {
            currentChat = await Chat.findOne({ _id: chatId, userId: req.user.id });
        }
        if (!currentChat) {
            const title = message ? message.substring(0, 30) : "Image Analysis";
            currentChat = new Chat({ userId: req.user.id, title, history: [] });
        }
        
        // Format the user's input for a multimodal AI model
        const userMessageContent = [];
        if (message) {
            userMessageContent.push({ type: "text", text: message });
        }
        if (imageFile) {
            const base64Image = imageFile.buffer.toString('base64');
            userMessageContent.push({
                type: "image_url",
                image_url: { "url": `data:${imageFile.mimetype};base64,${base64Image}` }
            });
        }
        currentChat.history.push({ role: 'user', content: userMessageContent });

        // Prepare the system prompt and full conversation history for the AI
        let systemInstructionText = `You are FarmWise Bot, an expert agricultural assistant. If the user uploads an image of a plant, your primary goal is to identify any visible diseases, pests, or nutrient deficiencies. Provide a concise diagnosis and suggest practical treatment options. If the user asks a general question, answer it helpfully.`;
        const languageMap = { 'ta': 'Tamil', 'ml': 'Malayalam' };
        if (language && languageMap[language]) {
            systemInstructionText += ` IMPORTANT: You must provide your entire response ONLY in the ${languageMap[language]} language.`;
        }

        const messagesForAPI = [
            { role: 'system', content: systemInstructionText },
            ...currentChat.history // History is already in the correct format for the API
        ];

        // Call the multimodal AI model
        const completion = await openrouter.chat.completions.create({
            model: "google/gemma-3-27b-it", // This model can process images and text
            messages: messagesForAPI,
        });

        const botReplyText = completion.choices[0].message?.content;

        if (!botReplyText) {
            throw new Error("AI model returned an empty response.");
        }
        
        // Save the AI's response to the chat history
        const botMessage = { role: 'assistant', content: botReplyText };
        currentChat.history.push(botMessage);
        await currentChat.save();

        res.json({ 
            reply: botReplyText, 
            newChatId: currentChat.isNew ? currentChat._id : undefined 
        });

    } catch (error) {
        console.error("Chat API Error:", error.message);
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
        const location = user.state || 'Coimbatore'; // Default to a location if user has no state set
        const apiKey = process.env.WEATHER_API_KEY;

        if (!apiKey) {
            throw new Error("Weather API key is not configured on the server.");
        }

        // 1. Get latitude and longitude for the location
        const geoUrl = `http://api.openweathermap.org/geo/1.0/direct?q=${location},IN&limit=1&appid=${apiKey}`;
        const geoResponse = await axios.get(geoUrl);
        if (!geoResponse.data || geoResponse.data.length === 0) {
            return res.status(404).json({ message: "Location not found." });
        }
        const { lat, lon } = geoResponse.data[0];

        // 2. Get the weather forecast using the coordinates
        const forecastUrl = `https://api.openweathermap.org/data/3.0/onecall?lat=${lat}&lon=${lon}&exclude=minutely,alerts&appid=${apiKey}&units=metric`;
        const forecastResponse = await axios.get(forecastUrl);
        
        res.json(forecastResponse.data);
    } catch (err) {
        console.error("Weather Forecast Error:", err.message);
        res.status(500).json({ message: "Could not fetch weather forecast." });
    }
});

module.exports = router;
