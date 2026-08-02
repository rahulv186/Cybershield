const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
    attack_type: {
        type: String,
        required: [true, 'Attack type is required'],
        trim: true,
        minLength: [1, 'Attack type cannot be empty']
    },
    severity: {
        type: String,
        enum: {
            values: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            message: '{VALUE} is not a valid severity'
        },
        required: [true, 'Severity is required']
    },
    detectedAt: {
        type: Date,
        default: Date.now
    },
    source_ip: {
        type: String,
        required: [true, 'Source IP is required'],
        trim: true,
        minLength: [1, 'Source IP cannot be empty']
    },
    destination_ip: {
        type: String,
        required: [true, 'Destination IP is required'],
        trim: true,
        minLength: [1, 'Destination IP cannot be empty']
    },
    protocol: {
        type: String,
        required: [true, 'Protocol is required'],
        trim: true,
        minLength: [1, 'Protocol cannot be empty']
    },
    description: {
        type: String,
        required: [true, 'Description is required'],
        trim: true,
        minLength: [1, 'Description cannot be empty']
    },
    evidence: {
        type: String,
        required: [true, 'Evidence is required'],
        trim: true,
        minLength: [1, 'Evidence cannot be empty']
    },
    recommendation: {
        type: String,
        required: [true, 'Recommendation is required'],
        trim: true,
        minLength: [1, 'Recommendation cannot be empty']
    }
}, { timestamps: true });

module.exports = mongoose.model('Threat', threatSchema, 'threats');
