require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000; // Use port provided by environment (e.g., Render)

// --- MIDDLEWARE ---
// 1. Enable CORS for all routes (important for connecting the separate frontend).
app.use(cors());

// 2. Enable Express body parsing for JSON data.
app.use(express.json());

// --- ROUTES ---
// Mount your API routes. All requests to /api/... will be handled here.
app.use('/api', require('./routes/api'));

// --- DATABASE CONNECTION OPTIONS ---
// Critical options for compatibility with MongoDB Atlas and Mongoose:
const dbOptions = {
    useNewUrlParser: true, 
    useUnifiedTopology: true 
    // We removed the unsupported options that caused previous errors.
};

// --- DATABASE CONNECTION & SERVER STARTUP ---
// Connect to the MongoDB Atlas cluster using the URI from your environment variables.
mongoose.connect(process.env.MONGODB_URI, dbOptions) 
    .then(() => {
        console.log('✅ MongoDB connected successfully.');
        
        // Start the server ONLY after the database is connected successfully.
        app.listen(PORT, () => {
            console.log(`🚀 Server is running on http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        // Log the specific error message for easier troubleshooting
        console.error('❌ MongoDB connection error:', err.message);
        console.error('ACTION: Check your MONGODB_URI in Render/local .env file (password, cluster name, database name, and parameters).');
        process.exit(1); 
    });
