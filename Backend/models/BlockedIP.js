const mongoose = require('mongoose');

const blockedIPSchema = new mongoose.Schema({
    blockedIP: {
        type: String,
        unique: true,
        required: [true, 'Blocked IP is required'],
        trim: true,
        minLength: [1, 'Blocked IP cannot be empty']
    },
    blockedAt: {
        type: Date,
        default: Date.now
    },
    reason: {
        type: mongoose.Schema.Types.Mixed,
        required: [true, 'Reason is required']
    }
}, { timestamps: true });

module.exports = mongoose.model('BlockedIP', blockedIPSchema, 'blocked_ips');
