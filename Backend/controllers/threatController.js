const Threat = require('../models/Threat');
const sendResponse = require('../utils/response');

// @desc    Create a new threat
// @route   POST /api/threats
const createThreat = async (req, res, next) => {
    try {
        const { attack_type, severity, detectedAt, source_ip, destination_ip, protocol, description, evidence, recommendation } = req.body;

        if (!attack_type || !severity || !detectedAt || !source_ip || !destination_ip || !protocol ||!description || !evidence || !recommendation) {
            return sendResponse(res, 400, false, 'All fields are required');
        }

        const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        if (!validSeverities.includes(severity)) {
            return sendResponse(res, 400, false, 'Invalid severity level');
        }

        const threat = await Threat.create(req.body);
        return sendResponse(res, 201, true, 'Threat stored successfully.', threat);
    } catch (error) {
        next(error);
    }
};

// @desc    Get all threats (newest first)
// @route   GET /api/threats
const getThreats = async (req, res, next) => {
    try {
        const threats = await Threat.find().sort({ detectedAt: -1 });
        return sendResponse(res, 200, true, 'Threats retrieved successfully.', threats);
    } catch (error) {
        next(error);
    }
};

// @desc    Get one threat by ID
// @route   GET /api/threats/:id
const getThreatById = async (req, res, next) => {
    try {
        const threat = await Threat.findById(req.params.id);
        if (!threat) {
            return sendResponse(res, 404, false, 'Threat not found.');
        }
        return sendResponse(res, 200, true, 'Threat retrieved successfully.', threat);
    } catch (error) {
        next(error);
    }
};

// @desc    Delete one threat
// @route   DELETE /api/threats/:id
const deleteThreat = async (req, res, next) => {
    try {
        const threat = await Threat.findByIdAndDelete(req.params.id);
        if (!threat) {
            return sendResponse(res, 404, false, 'Threat not found.');
        }
        return sendResponse(res, 200, true, 'Threat deleted successfully.');
    } catch (error) {
        next(error);
    }
};

// @desc    Delete all threats
// @route   DELETE /api/threats
const deleteAllThreats = async (req, res, next) => {
    try {
        await Threat.deleteMany({});
        return sendResponse(res, 200, true, 'All threats deleted successfully.');
    } catch (error) {
        next(error);
    }
};

// @desc    Filter threats
// @route   GET /api/threats/filter
const filterThreats = async (req, res, next) => {
    try {
        const { severity, attack_type, source_ip, protocol, startDate, endDate } = req.query;
        let query = {};

        if (severity) query.severity = severity;
        if (attack_type) query.attack_type = attack_type;
        if (source_ip) query.source_ip = source_ip;
        if (protocol) query.protocol = protocol;

        if (startDate || endDate) {
            query.detectedAt = {};
            if (startDate) query.detectedAt.$gte = new Date(startDate);
            if (endDate) query.detectedAt.$lte = new Date(endDate);
        }

        const threats = await Threat.find(query).sort({ detectedAt: -1 });
        return sendResponse(res, 200, true, 'Filtered threats retrieved successfully.', threats);
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createThreat,
    getThreats,
    getThreatById,
    deleteThreat,
    deleteAllThreats,
    filterThreats
};
