const BlockedIP = require('../models/BlockedIP');
const sendResponse = require('../utils/response');
const axios = require('axios');

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

// @desc    Unblock and remove blocked IP
// @route   DELETE /api/blocked/:ip
const deleteBlockedIP = async (req, res, next) => {
    try {
        const { ip } = req.params;

        if (!ip || ip.trim() === '') {
            return sendResponse(res, 400, false, 'IP address is required.');
        }

        // Ask Python local server to remove the firewall rule
        try {
            const response = await axios.post(
                'http://127.0.0.1:5060/api/unblock',
                {
                    ip: ip.trim()
                },
                {
                    timeout: 5000
                }
            );

            if (!response.data?.success) {
                return sendResponse(
                    res,
                    500,
                    false,
                    'Failed to unblock IP from firewall.'
                );
            }

        } catch (pythonError) {
            console.error(
                '[PYTHON UNBLOCK ERROR]',
                pythonError.response?.data || pythonError.message
            );

            return sendResponse(
                res,
                503,
                false,
                'Python security server is unavailable. IP was not removed.'
            );
        }

        // Only remove from MongoDB after firewall unblock succeeds
        const deletedIP = await BlockedIP.findOneAndDelete({
            blockedIP: ip.trim()
        });

        if (!deletedIP) {
            return sendResponse(
                res,
                404,
                false,
                'IP was unblocked, but no matching database record was found.'
            );
        }

        return sendResponse(
            res,
            200,
            true,
            'IP unblocked and removed successfully.'
        );

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
