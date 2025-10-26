const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Used for auth routes only
const multer = require('multer');
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

// --- GEMINI CLIENT INITIALIZATION ---
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

// =============== CHATBOT ROUTE ===============
router.post('/chat', authMiddleware, upload.single('image'), async (req, res) => {
    const { message, chatId, language } = req.body;
    const imageFile = req.file;

    if (!message && !imageFile) {
        return res.status(400).json({ message: 'A message or an image is required.' });
    }

    try {
        let currentChat;
        let isNewChat = false;
        let historyForAPI = []; 

        if (chatId) {
            currentChat = await Chat.findOne({ _id: chatId, userId: req.user.id });
            if (currentChat) {
                historyForAPI = currentChat.history;
            }
        }
        
        if (!currentChat) {
            const title = message ? message.substring(0, 35) : "New Image Analysis";
            currentChat = new Chat({ userId: req.user.id, title, history: [] });
            isNewChat = true;
        }

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

        const chatSession = geminiModel.startChat({
            history: historyForAPI,
            safetySettings,
            systemInstruction: systemInstructionText,
        });

        const result = await chatSession.sendMessage(userMessageParts);
        const response = result.response;
        const botReplyText = response.text();

        if (!botReplyText) {
            throw new Error("AI model returned an empty response.");
        }

        currentChat.history.push({ role: 'user', parts: userMessageParts });
        currentChat.history.push({ role: 'model', parts: [{ text: botReplyText }] });
        await currentChat.save();
        
        res.json({ 
            reply: botReplyText,
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
router.get('/chats', authMiddleware, async (req, res) => {
    try {
        // --- FIX: Added .select() to only fetch necessary data ---
        const chats = await Chat.find({ userId: req.user.id })
            .select('title createdAt updatedAt') // Only get the title and dates
            .sort({ updatedAt: -1 }); // Sort by most recently updated
        res.json(chats);
    } catch (err) {
        console.error("Fetch Chats Error:", err.message);
        res.status(500).json({ message: 'Server error fetching chats.' });
    }
});

router.get('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
        // This is correct: it fetches the full chat object (title, history, etc.)
        // for the chat the user clicked on.
        const chat = await Chat.findOne({ _id: req.params.chatId, userId: req.user.id });
        if (!chat) {
            return res.status(404).json({ message: 'Chat not found.' });
        }
        res.json(chat); // Send the full chat object
    } catch (err) {
        console.error("Fetch Chat Error:", err.message);
        res.status(500).json({ message: 'Server error fetching chat.' });
    }
});

router.delete('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
        const chat = await Chat.findOneAndDelete({ _id: req.params.chatId, userId: req.user.id });
        if (!chat) {
            return res.status(404).json({ message: 'Chat not found.' });
        }
        res.json({ message: 'Chat deleted.' });
    } catch (err) {
        console.error("Delete Chat Error:", err.message);
        res.status(500).json({ message: 'Server error deleting chat.' });
    }
});

// =============== WEATHER ROUTE WITH GEMINI AI ===============

// --- BUG FIX: Added a second item to hourly/daily arrays ---
// This teaches the AI to return a list, not a single object.
const getForecastJsonStructure = () => ({
    current: { temp: 29.5, feels_like: 32.1, humidity: 78, wind_speed: 5.1, weather: [{ description: "scattered clouds", icon: "03d", main: "Clouds" }] },
    hourly: [ 
        { dt: 1664191200, temp: 28.5, weather: [{ icon: "04n", main: "Clouds" }] },
        { dt: 1664194800, temp: 28.2, weather: [{ icon: "04n", main: "Clouds" }] } // Added second item
    ],
    daily: [ 
        { dt: 1664166600, temp: { min: 24.5, max: 32.8 }, weather: [{ icon: "03d", main: "Clouds" }] },
        { dt: 1664253000, temp: { min: 24.1, max: 32.1 }, weather: [{ icon: "10d", main: "Rain" }] } // Added second item
    ]
});

router.get('/weather/forecast', authMiddleware, async (req, res) => {
    try {
        // 1. Get user's location from their profile
        const user = await User.findById(req.user.id);
        const location = user?.state || 'Coimbatore'; // Default if user has no state

        // 2. Create a detailed prompt for Gemini
        const prompt = `
            You are a weather API. A user needs a weather forecast for ${location}, India.
            You must provide the current weather, a 12-hour hourly forecast, and a 7-day daily forecast.
            IMPORTANT: You must ONLY respond with a single, minified JSON object. 
            Do not include any text, backticks, or markdown before or after the JSON.
            The JSON structure MUST match this example:
            ${JSON.stringify(getForecastJsonStructure())}
            Fill in the data with realistic, current weather information for ${location}, India. 
            - 'dt' (timestamp) fields should be correct for the current date and time.
            - 'icon' codes must be valid OpenWeatherMap icon codes (e.g., "01d", "04n", "10d").
            - 'wind_speed' should be in m/s (metric units).
            - The 'hourly' array must contain exactly 12 items.
            - The 'daily' array must contain exactly 7 items.
        `;
        
        // 3. Call the Gemini model
        const result = await geminiModel.generateContent(prompt);
        const response = result.response;
        const forecastText = response.text();

        // 4. Parse the text response as JSON
        let forecastJSON;
        try {
            forecastJSON = JSON.parse(forecastText);
        } catch (parseError) {
            console.error("Gemini JSON Parse Error:", parseError.message);
            console.error("Gemini Raw Response:", forecastText);
            throw new Error("AI model returned invalid JSON.");
        }

        // 5. Send the parsed JSON and location name to the client
        res.json({ 
            forecast: forecastJSON,
            location: location 
        });

    } catch (err) {
        console.error("Weather Forecast Error (Gemini):", err.message);
        res.status(500).json({ message: "Could not fetch the weather forecast." });
    }
});

module.exports = router;
