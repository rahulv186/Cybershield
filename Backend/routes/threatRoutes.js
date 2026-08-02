const express = require('express');
const router = express.Router();
const {
    createThreat,
    getThreats,
    getThreatById,
    deleteThreat,
    deleteAllThreats,
    filterThreats
} = require('../controllers/threatController');

router.get('/filter', filterThreats);

router.route('/')
    .get(getThreats)
    .post(createThreat)
    .delete(deleteAllThreats);

router.route('/:id')
    .get(getThreatById)
    .delete(deleteThreat);

module.exports = router;
