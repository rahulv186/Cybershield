const sendResponse = require('../utils/response');

const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    
    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const message = Object.values(err.errors).map(val => val.message).join(', ');
        return sendResponse(res, 400, false, message);
    }

    sendResponse(res, 500, false, 'Server Error', { error: err.message });
};

module.exports = errorHandler;
