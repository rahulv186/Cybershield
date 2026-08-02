const express = require('express');
const router = express.Router();
const {
    createBlockedIP,
    getBlockedIPs,
    deleteBlockedIP,
    deleteAllBlockedIPs
} = require('../controllers/blockedIPController');

router.route('/')
    .get(getBlockedIPs)
    .post(createBlockedIP)
    .delete(deleteAllBlockedIPs);

router.route('/:ip')
    .delete(deleteBlockedIP);

module.exports = router;
