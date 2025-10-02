const AuditLog = require('../models/AuditLog');

/**
 * Global error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error to console in development
  if (process.env.NODE_ENV === 'development') {
    console.error('Error Stack:', err.stack);
  }

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Invalid resource ID format';
    error = {
      message,
      statusCode: 400,
      code: 'INVALID_ID_FORMAT'
    };
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `Duplicate value for field: ${field}`;
    error = {
      message,
      statusCode: 400,
      code: 'DUPLICATE_FIELD',
      field: field
    };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message).join(', ');
    error = {
      message,
      statusCode: 400,
      code: 'VALIDATION_ERROR',
      errors: Object.keys(err.errors)
    };
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = {
      message: 'Invalid token',
      statusCode: 401,
      code: 'INVALID_TOKEN'
    };
  }

  if (err.name === 'TokenExpiredError') {
    error = {
      message: 'Token expired',
      statusCode: 401,
      code: 'TOKEN_EXPIRED'
    };
  }

  // Rate limit errors
  if (err.statusCode === 429) {
    error = {
      message: 'Too many requests, please try again later',
      statusCode: 429,
      code: 'RATE_LIMIT_EXCEEDED'
    };
  }

  // File upload errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    error = {
      message: 'File too large',
      statusCode: 400,
      code: 'FILE_TOO_LARGE'
    };
  }

  // IPFS/Pinata errors
  if (err.message && err.message.includes('Pinata')) {
    error = {
      message: 'IPFS storage error',
      statusCode: 503,
      code: 'IPFS_ERROR'
    };
  }

  // Blockchain/Ethereum errors
  if (err.message && (err.message.includes('revert') || err.message.includes('gas'))) {
    error = {
      message: 'Blockchain transaction failed',
      statusCode: 400,
      code: 'BLOCKCHAIN_ERROR',
      details: err.message
    };
  }

  // Default to 500 server error
  const statusCode = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';
  const code = error.code || 'INTERNAL_ERROR';

  // Create audit log for errors
  const auditData = {
    action: 'api_error',
    category: 'system',
    severity: statusCode >= 500 ? 'error' : 'warning',
    status: 'failure',
    description: `${req.method} ${req.path} - ${message}`,
    metadata: {
      statusCode,
      code,
      errorName: err.name,
      originalMessage: err.message
    },
    requestData: {
      method: req.method,
      url: req.originalUrl,
      headers: sanitizeHeaders(req.headers),
      body: sanitizeBody(req.body),
      query: req.query,
      params: req.params
    },
    responseData: {
      statusCode,
      responseTime: Date.now() - req.startTime
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    },
    errorInfo: {
      errorCode: code,
      errorMessage: message,
      stackTrace: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      errorType: err.name
    }
  };

  // Add user info if available
  if (req.user) {
    auditData.user = req.user.id;
    auditData.sessionInfo = {
      userId: req.user.id,
      walletAddress: req.user.walletAddress
    };
  }

  // Create audit log (don't await to avoid blocking response)
  AuditLog.createLog(auditData).catch(logError => {
    console.error('Failed to create audit log:', logError);
  });

  // Send error response
  const response = {
    success: false,
    error: {
      message,
      code,
      statusCode
    }
  };

  // Add additional error details in development
  if (process.env.NODE_ENV === 'development') {
    response.error.stack = err.stack;
    response.error.details = error.details;
    if (error.errors) {
      response.error.validationErrors = error.errors;
    }
    if (error.field) {
      response.error.duplicateField = error.field;
    }
  }

  res.status(statusCode).json(response);
};

/**
 * Async error handler wrapper
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * 404 Not Found handler
 */
const notFound = (req, res, next) => {
  const error = new Error(`Route not found - ${req.originalUrl}`);
  error.statusCode = 404;
  error.code = 'ROUTE_NOT_FOUND';
  next(error);
};

/**
 * Validation error handler
 */
const validationError = (errors) => {
  const error = new Error('Validation failed');
  error.statusCode = 400;
  error.code = 'VALIDATION_ERROR';
  error.errors = errors;
  return error;
};

/**
 * Custom error class
 */
class AppError extends Error {
  constructor(message, statusCode, code) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Helper function to sanitize headers (remove sensitive data)
 */
function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  delete sanitized.authorization;
  delete sanitized.cookie;
  delete sanitized['x-api-key'];
  return sanitized;
}

/**
 * Helper function to sanitize request body (remove sensitive data)
 */
function sanitizeBody(body) {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };
  
  // Remove sensitive fields
  const sensitiveFields = [
    'password',
    'passwordHash',
    'token',
    'apiKey',
    'privateKey',
    'secret',
    'creditCard',
    'ssn',
    'socialSecurityNumber'
  ];

  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
}

module.exports = {
  errorHandler,
  asyncHandler,
  notFound,
  validationError,
  AppError
};
