const Threat = require('../models/Threat');
const BlockedIP = require('../models/BlockedIP');
const sendResponse = require('../utils/response');

// @desc    Get system stats
// @route   GET /api/stats
const getStats = async (req, res, next) => {
    try {
        const totalThreats = await Threat.countDocuments();
        const highSeverity = await Threat.countDocuments({ severity: 'HIGH' });
        const criticalSeverity = await Threat.countDocuments({ severity: 'CRITICAL' });
        const blockedIPs = await BlockedIP.countDocuments();

        const topAttackTypes = await Threat.aggregate([
            { $group: { _id: "$attack_type", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);

        const topSourceIPs = await Threat.aggregate([
            { $group: { _id: "$source_ip", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);

        const stats = {
            totalThreats,
            highSeverity,
            criticalSeverity,
            blockedIPs,
            topAttackTypes,
            topSourceIPs
        };

        return sendResponse(res, 200, true, 'Stats retrieved successfully.', stats);
    } catch (error) {
        next(error);
    }
};

module.exports = { getStats };
