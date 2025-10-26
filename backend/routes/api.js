const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
// SDK is removed, ensure node-fetch or similar is available if using older Node.js
// If Node.js v18+, fetch is built-in.
require('dotenv').config();

// --- DATABASE MODELS ---
const User = require('../models/User');
const Chat = require('../models/chat');

// --- INITIALIZATION ---
const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// --- GEMINI API DETAILS ---
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL_NAME = "gemini-2.0-flash"; // Or your preferred model
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL_NAME}:generateContent?key=${GEMINI_API_KEY}`;

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

// --- USER AUTHENTICATION ROUTES ---
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

// --- CHATBOT ROUTE (Using fetch) ---
router.post('/chat', authMiddleware, upload.single('image'), async (req, res) => {
    const { message, chatId, language } = req.body;
    const imageFile = req.file;

    if (!message && !imageFile) {
        return res.status(400).json({ message: 'A message or an image is required.' });
    }

    try {
        let currentChat;
        let isNewChat = false;
        let historyForAPI = []; // Will hold history in { role, parts } format

        if (chatId) {
            currentChat = await Chat.findOne({ _id: chatId, userId: req.user.id });
            if (currentChat) {
                // Ensure history is in the correct format before sending
                historyForAPI = currentChat.history.map(msg => ({
                    role: msg.role === 'user' ? 'user' : 'model', // Map roles
                    parts: msg.parts // Assuming parts are already correct
                }));
            }
        }

        if (!currentChat) {
            const title = message ? message.substring(0, 35) : "New Image Analysis";
            currentChat = new Chat({ userId: req.user.id, title, history: [] });
            isNewChat = true;
        }

        // --- Build the new user message parts ---
        const userMessageParts = [];
        if (imageFile) {
            userMessageParts.push({
                inlineData: {
                    mimeType: imageFile.mimetype,
                    data: imageFile.buffer.toString('base64')
                }
            });
        }
        // Ensure there's always a text part, even if empty, if only image is sent
        // OR handle the case where message might be empty but image exists
        if (message || !imageFile) {
            userMessageParts.push({ text: message || "" }); // Add empty text if only image
        }


        // --- Prepare the full request payload ---
        let systemInstructionText = `You are FarmWise Bot, an expert agricultural assistant. If a user uploads a plant image, identify diseases, pests, or deficiencies and suggest treatments. For general questions, provide helpful, concise farming advice.`;
        const languageMap = { 'ta': 'Tamil', 'ml': 'Malayalam' };
        if (language && languageMap[language]) {
            systemInstructionText += ` IMPORTANT: You must provide your entire response ONLY in the ${languageMap[language]} language.`;
        }

        const safetySettings = [
            { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
            { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
            { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
            { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
        ];

        // Combine history and the new message
        const contents = [
            ...historyForAPI,
            { role: "user", parts: userMessageParts }
        ];

        const requestBody = {
            contents: contents,
            safetySettings: safetySettings,
            systemInstruction: {
                 parts: [{ text: systemInstructionText }]
            },
            generationConfig: { /* Optional config */ }
        };

        // --- Make the fetch call ---
        const geminiResponse = await fetch(GEMINI_API_URL, { // Use consistent URL
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        if (!geminiResponse.ok) {
            const errorBody = await geminiResponse.json().catch(() => ({}));
            console.error("Gemini API Error Response:", errorBody);
            throw new Error(`Gemini API request failed with status ${geminiResponse.status}: ${errorBody.error?.message || 'Unknown error'}`);
        }

        const responseData = await geminiResponse.json();

        // --- Process the response ---
        if (responseData.promptFeedback && responseData.promptFeedback.blockReason) {
             console.error("Prompt Feedback (Blocked):", responseData.promptFeedback);
             return res.status(400).json({ message: `Request blocked due to safety settings: ${responseData.promptFeedback.blockReason}`, details: responseData.promptFeedback });
         }

        const botReplyText = responseData.candidates?.[0]?.content?.parts?.[0]?.text;

        if (botReplyText === undefined || botReplyText === null) { // Check specifically for undefined/null
             console.error("Gemini API - No text content found in response:", JSON.stringify(responseData, null, 2));
             // Check finish reason if available
             const finishReason = responseData.candidates?.[0]?.finishReason;
             if (finishReason && finishReason !== "STOP") {
                 throw new Error(`AI model generation finished unexpectedly: ${finishReason}`);
             } else {
                throw new Error("AI model returned an empty or invalid response structure.");
             }
        }


        // --- Save history in the database format ---
        // Ensure user parts saved match what was sent
        currentChat.history.push({ role: 'user', parts: userMessageParts });
        currentChat.history.push({ role: 'model', parts: [{ text: botReplyText }] });
        await currentChat.save();

        res.json({
            reply: botReplyText,
            newChatId: isNewChat ? currentChat._id : undefined
        });

    } catch (error) {
        console.error("Chat API Error:", error.message);
         if (!res.headersSent) {
            res.status(500).json({ message: error.message || 'Failed to get a response from the AI model.' });
         }
    }
});


// --- CHAT HISTORY ROUTES ---
// GET /api/chats
router.get('/chats', authMiddleware, async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user.id })
            .select('title createdAt updatedAt')
            .sort({ updatedAt: -1 });
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
        res.json(chat);
    } catch (err) {
        console.error("Get Chat History Error:", err.message);
        res.status(500).json({ message: 'Server error fetching chat history.' });
    }
});

// DELETE /api/chat/:chatId
router.delete('/chat/:chatId', authMiddleware, async (req, res) => {
    try {
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

// --- WEATHER ROUTE (USING fetch) ---

// Correct structure example for the AI
const getForecastJsonStructure = () => ({
    current: { temp: 29.5, feels_like: 32.1, humidity: 78, wind_speed: 5.1, weather: [{ description: "scattered clouds", icon: "03d", main: "Clouds" }] },
    hourly: [
        { dt: 1664191200, temp: 28.5, weather: [{ icon: "04n", main: "Clouds" }] },
        { dt: 1664194800, temp: 28.2, weather: [{ icon: "04n", main: "Clouds" }] }
    ],
    daily: [
        { dt: 1664166600, temp: { min: 24.5, max: 32.8 }, weather: [{ icon: "03d", main: "Clouds" }] },
        { dt: 1664253000, temp: { min: 24.1, max: 32.1 }, weather: [{ icon: "10d", main: "Rain" }] }
    ]
});

// GET /api/weather/forecast
router.get('/weather/forecast', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const location = user?.state || 'Coimbatore';

        const prompt = `
            You are a weather API. A user needs a weather forecast for ${location}, India.
            You must provide the current weather, a 12-hour hourly forecast, and a 7-day daily forecast.
            IMPORTANT: You must ONLY respond with a single, minified JSON object.
            Do not include any text, backticks, markdown, or anything else before or after the JSON object.
            The JSON structure MUST exactly match this example:
            ${JSON.stringify(getForecastJsonStructure())}
            Fill in the data with realistic, current weather information for ${location}, India.
            - 'dt' (timestamp) fields should be correct UTC timestamps for the current date and time. Use standard Unix timestamps (seconds since epoch).
            - 'icon' codes must be valid OpenWeatherMap icon codes (like "01d", "04n", "10d").
            - 'wind_speed' should be in meters per second (m/s).
            - The 'hourly' array must contain exactly 12 items, representing the next 12 hours starting from the current hour.
            - The 'daily' array must contain exactly 7 items, representing today and the next 6 days.
        `;

        // --- Make the fetch call ---
        const geminiResponse = await fetch(GEMINI_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                 // Add safety settings similar to chat if needed
                 safetySettings: [
                     { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
                     { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
                     { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
                     { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_MEDIUM_AND_ABOVE" },
                 ],
                 generationConfig: {
                    // Force JSON output if model supports it (check Gemini docs)
                    // responseMimeType: "application/json",
                     temperature: 0.5 // Lower temp might help consistency
                 }
            })
        });

        if (!geminiResponse.ok) {
            const errorBody = await geminiResponse.json().catch(() => ({}));
            console.error("Gemini Weather API Error Response:", errorBody);
            throw new Error(`Gemini API request failed with status ${geminiResponse.status}: ${errorBody.error?.message || 'Unknown error'}`);
        }

        const responseData = await geminiResponse.json();

         // Check for safety blocks
         if (responseData.promptFeedback && responseData.promptFeedback.blockReason) {
             console.error("Weather Prompt Feedback (Blocked):", responseData.promptFeedback);
             return res.status(400).json({ message: `Weather request blocked due to safety settings: ${responseData.promptFeedback.blockReason}`, details: responseData.promptFeedback });
         }

        const forecastText = responseData.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!forecastText) {
             console.error("Gemini Weather API - No text content found:", JSON.stringify(responseData, null, 2));
             const finishReason = responseData.candidates?.[0]?.finishReason;
             if (finishReason && finishReason !== "STOP") {
                 throw new Error(`AI model weather generation finished unexpectedly: ${finishReason}`);
             } else {
                 throw new Error("AI model returned empty or invalid weather data structure.");
             }
        }


        // Parse the JSON text
        let forecastJSON;
        try {
            // Be robust against potential markdown wrappers
            const cleanText = forecastText
                .trim() // Remove leading/trailing whitespace
                .replace(/^```json\s*/, '') // Remove starting ```json (optional whitespace)
                .replace(/\s*```$/, '');    // Remove ending ``` (optional whitespace)
            forecastJSON = JSON.parse(cleanText);
            // Basic validation of the parsed structure
            if (!forecastJSON.current || !Array.isArray(forecastJSON.hourly) || !Array.isArray(forecastJSON.daily)) {
                throw new Error("Parsed JSON lacks required structure (current, hourly, daily).");
            }
        } catch (parseError) {
            console.error("Gemini Weather JSON Parse Error:", parseError.message);
            console.error("Gemini Weather Raw Response:", forecastText); // Log the bad response
            throw new Error("AI model returned invalid JSON format for weather.");
        }

        res.json({
            forecast: forecastJSON,
            location: location
        });

    } catch (err) {
        console.error("Weather Forecast Error (Gemini Fetch):", err.message);
         if (!res.headersSent) {
            res.status(500).json({ message: err.message || "Could not fetch the weather forecast." });
         }
    }
});

module.exports = router;
