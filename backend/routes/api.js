const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const multer = require('multer');
// --- NEW GOOGLE PACKAGE ---
const { 
    GoogleGenerativeAI, 
    HarmCategory, 
    HarmBlockThreshold 
} = require("@google/generative-ai");
require('dotenv').config();

// --- DATABASE MODELS ---
const User = require('../models/User');
const Chat = require('../models/chat');

// --- INITIALIZATION ---
const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// --- NEW GEMINI CLIENT INITIALIZATION ---
// Make sure you have GEMINI_API_KEY in your .env file
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiModel = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

// --- AUTHENTICATION MIDDLEWARE ---
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
// (These routes are unchanged)

// POST /api/signup
router.post('/signup', async (req, res) => {
    const { username, email, phone, password, state } = req.body;
    try {
        if (!username || !email || !phone || !password || !state) {
            return res.status(400).json({ message: 'Please enter all required fields.' });
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
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

// POST /api/login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// GET /api/profile
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.json(user);
    } catch (err) {
        console.error("Profile Error:", err.message);
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});

// =============== CHATBOT ROUTE (HEAVILY MODIFIED) ===============

router.post('/chat', authMiddleware, upload.single('image'), async (req, res) => {
    const { message, chatId, language } = req.body;
    const imageFile = req.file;

    if (!message && !imageFile) {
        return res.status(400).json({ message: 'A message or an image is required.' });
    }

    try {
        let currentChat;
        let isNewChat = false;
        let historyForAPI = []; // This will be in Google's format

        if (chatId) {
            currentChat = await Chat.findOne({ _id: chatId, userId: req.user.id });
            if (currentChat) {
                // IMPORTANT: Assumes history is already in Google's format
                // { role: "user", parts: [{...}] }
                // { role: "model", parts: [{...}] }
                historyForAPI = currentChat.history;
            }
        }
        
        if (!currentChat) {
            const title = message ? message.substring(0, 35) : "New Image Analysis";
            // Note: history is initialized empty, which is fine
            currentChat = new Chat({ userId: req.user.id, title, history: [] });
            isNewChat = true;
        }

        // --- Build the new user message in Google's format ---
        const userMessageParts = [];
        if (imageFile) {
            userMessageParts.push({
                inlineData: {
                    data: imageFile.buffer.toString('base64'),
                    mimeType: imageFile.mimetype
                }
            });
        }
        if (message) {
            userMessageParts.push({ text: message });
        }

        // --- System Instruction and Safety ---
        let systemInstructionText = `You are FarmWise Bot, an expert agricultural assistant. If a user uploads a plant image, identify diseases, pests, or deficiencies and suggest treatments. For general questions, provide helpful, concise farming advice.`;
        const languageMap = { 'ta': 'Tamil', 'ml': 'Malayalam' };
        if (language && languageMap[language]) {
            systemInstructionText += ` IMPORTANT: You must provide your entire response ONLY in the ${languageMap[language]} language.`;
        }

        const safetySettings = [
            { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
            { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
            { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
            { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
        ];

        // --- Start a chat session with history and system prompt ---
        const chatSession = geminiModel.startChat({
            history: historyForAPI,
            safetySettings,
            systemInstruction: systemInstructionText,
        });

        // --- Send the new user message ---
        const result = await chatSession.sendMessage(userMessageParts);
        const response = result.response;
        const botReplyText = response.text();

        if (!botReplyText) {
            throw new Error("AI model returned an empty response.");
        }

        // --- Save history in the new Google format ---
        currentChat.history.push({ role: 'user', parts: userMessageParts });
        currentChat.history.push({ role: 'model', parts: [{ text: botReplyText }] }); // 'model' is Google's role for the assistant
        await currentChat.save();
        
        res.json({ 
            reply: botReplyText,s
            newChatId: isNewChat ? currentChat._id : undefined 
        });

    } catch (error) {
        console.error("Chat API Error:", error.message);
        if (error.response && error.response.promptFeedback) {
             console.error("Prompt Feedback:", error.response.promptFeedback);
             return res.status(400).json({ message: 'Request blocked due to safety settings.', details: error.response.promptFeedback });
        }
        res.status(500).json({ message: 'Failed to get a response from the AI model.' });
    }
});

// =============== CHAT HISTORY ROUTES ===============
// (Unchanged, but note the data format returned by /chat/:chatId is different)

// GET /api/chats
router.get('/chats', authMiddleware, async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user.id }).select('title createdAt').sort({ createdAt: -1 });
        res.json(chats);
    } catch (err) {
        console.error("Get Chats Error:", err.message);
        res.status(500).json({ message: 'Server error fetching chats.' });
    }
});

// GET /api/chat/:chatId
router.get('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
        const chat = await Chat.findOne({ _id: req.params.chatId, userId: req.user.id });
        if (!chat) {
            return res.status(404).json({ message: 'Chat not found.' });
        }
        // This now returns history in Google's format:
        // [{ role: "user", parts: [...] }, { role: "model", parts: [...] }]
        res.json(chat.history);
    } catch (err) {
        console.error("Get Chat History Error:", err.message);
        res.status(500).json({ message: 'Server error fetching chat history.' });
    }
});

// DELETE /api/chat/:chatId
router.delete('/chat/:chatId', authMiddleware, async (req, res) => {
s   try {
        const { chatId } = req.params;
        const result = await Chat.findOneAndDelete({ _id: chatId, userId: req.user.id });
        if (!result) {
            return res.status(404).json({ message: 'Chat not found or you do not have permission.' });
        }
        res.json({ message: 'Chat deleted successfully.' });
    } catch (err) {
        console.error("Delete Chat Error:", err.message);
        res.status(500).json({ message: 'Server error deleting chat.' });
    }
});

// =============== WEATHER ROUTE ===============
// (Unchanged)

// GET /api/weather/forecast
router.get('/weather/forecast', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const location = user?.state || 'Coimbatore';
        const apiKey = process.env.WEATHER_API_KEY;

        if (!apiKey) {
            return res.status(500).json({ message: "Weather service is not configured." });
        }

        const geoUrl = `http://api.openweathermap.org/geo/1.0/direct?q=${location},IN&limit=1&appid=${apiKey}`;
        const geoResponse = await axios.get(geoUrl);
        if (!geoResponse.data || geoResponse.data.length === 0) {
            return res.status(404).json({ message: "Location could not be found." });
      A }
        const { lat, lon } = geoResponse.data[0];

        const forecastUrl = `https://api.openweathermap.org/data/3.0/onecall?lat=${lat}&lon=${lon}&exclude=minutely,alerts&appid=${apiKey}&units=metric`;
        const forecastResponse = await axios.get(forecastUrl);
        res.json(forecastResponse.data);
    } catch (err) {
        console.error("Weather Forecast Error:", err.message);
        res.status(500).json({ message: "Could not fetch the weather forecast." });
    }
});

module.exports = router;
