const BlockedIP = require('../models/BlockedIP');
const sendResponse = require('../utils/response');

// @desc    Store blocked IP
// @route   POST /api/blocked
const createBlockedIP = async (req, res, next) => {
    try {
        const { blockedIP, reason } = req.body;

        if (!blockedIP || blockedIP.trim() === '') {
            return sendResponse(res, 400, false, 'Blocked IP is required');
        }

        const existingIP = await BlockedIP.findOne({ blockedIP });
        if (existingIP) {
            return sendResponse(res, 409, false, 'IP is already blocked.');
        }

        const newBlockedIP = await BlockedIP.create({ blockedIP, reason });
        return sendResponse(res, 201, true, 'IP blocked successfully.', newBlockedIP);
    } catch (error) {
        next(error);
    }
};

// @desc    Get all blocked IPs
// @route   GET /api/blocked
const getBlockedIPs = async (req, res, next) => {
    try {
        const blockedIPs = await BlockedIP.find().sort({ blockedAt: -1 });
        return sendResponse(res, 200, true, 'Blocked IPs retrieved successfully.', blockedIPs);
    } catch (error) {
        next(error);
    }
};

// @desc    Remove blocked IP
// @route   DELETE /api/blocked/:ip
const deleteBlockedIP = async (req, res, next) => {
    try {
        const { ip } = req.params;
        const deletedIP = await BlockedIP.findOneAndDelete({ blockedIP: ip });

        if (!deletedIP) {
            return sendResponse(res, 404, false, 'Blocked IP not found.');
        }

        return sendResponse(res, 200, true, 'Blocked IP removed successfully.');
    } catch (error) {
        next(error);
    }
};

// @desc    Remove all blocked IPs
// @route   DELETE /api/blocked
const deleteAllBlockedIPs = async (req, res, next) => {
    try {
        await BlockedIP.deleteMany({});
        return sendResponse(res, 200, true, 'All blocked IPs removed successfully.');
    } catch (error) {
        next(error);
    }
};

module.exports = {
    createBlockedIP,
    getBlockedIPs,
    deleteBlockedIP,
    deleteAllBlockedIPs
};
