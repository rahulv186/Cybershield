require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const connectDB = require('./config/db');
const errorHandler = require('./middleware/errorHandler');

// Route files
const threatRoutes = require('./routes/threatRoutes');
const blockedIPRoutes = require('./routes/blockedIPRoutes');
const statsRoutes = require('./routes/statsRoutes');

// Connect to database
connectDB();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

// Mount routers
app.use('/api/threats', threatRoutes);
app.use('/api/blocked', blockedIPRoutes);
app.use('/api/stats', statsRoutes);

// Error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 5050;

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
