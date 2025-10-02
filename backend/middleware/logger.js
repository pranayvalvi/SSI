const AuditLog = require('../models/AuditLog');

/**
 * Request logging middleware
 */
const requestLogger = (req, res, next) => {
  // Record start time for response time calculation
  req.startTime = Date.now();
  
  // Generate correlation ID for request tracking
  req.correlationId = generateCorrelationId();
  
  // Add correlation ID to response headers
  res.set('X-Correlation-ID', req.correlationId);
  
  // Log request in development
  if (process.env.NODE_ENV === 'development') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${req.ip}`);
  }
  
  // Override res.json to capture response data
  const originalJson = res.json;
  res.json = function(data) {
    res.responseData = data;
    return originalJson.call(this, data);
  };
  
  // Log request completion
  res.on('finish', () => {
    logRequest(req, res);
  });
  
  next();
};

/**
 * Log API request details
 */
async function logRequest(req, res) {
  try {
    const responseTime = Date.now() - req.startTime;
    const statusCode = res.statusCode;
    
    // Determine log level based on status code
    let severity = 'info';
    let status = 'success';
    
    if (statusCode >= 400 && statusCode < 500) {
      severity = 'warning';
      status = 'failure';
    } else if (statusCode >= 500) {
      severity = 'error';
      status = 'failure';
    }
    
    // Skip logging for health checks and static assets
    if (shouldSkipLogging(req.path)) {
      return;
    }
    
    const logData = {
      action: 'api_call',
      category: 'api',
      severity: severity,
      status: status,
      description: `${req.method} ${req.path} - ${statusCode}`,
      correlationId: req.correlationId,
      metadata: {
        endpoint: `${req.method} ${req.path}`,
        statusCode: statusCode,
        responseTime: responseTime,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer')
      },
      requestData: {
        method: req.method,
        url: req.originalUrl,
        headers: sanitizeHeaders(req.headers),
        body: sanitizeRequestBody(req.body),
        query: req.query,
        params: req.params
      },
      responseData: {
        statusCode: statusCode,
        headers: sanitizeHeaders(res.getHeaders()),
        body: sanitizeResponseBody(res.responseData),
        responseTime: responseTime
      },
      clientInfo: {
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent'),
        browser: parseBrowser(req.get('User-Agent')),
        os: parseOS(req.get('User-Agent'))
      }
    };
    
    // Add user info if available
    if (req.user) {
      logData.user = req.user.id;
      logData.sessionInfo = {
        userId: req.user.id,
        walletAddress: req.user.walletAddress
      };
    }
    
    // Add issuer info if available
    if (req.issuer) {
      logData.issuer = req.issuer._id;
    }
    
    // Create audit log (async, don't block response)
    AuditLog.createLog(logData).catch(error => {
      console.error('Failed to create request log:', error);
    });
    
  } catch (error) {
    console.error('Request logging error:', error);
  }
}

/**
 * Security event logger
 */
const logSecurityEvent = async (eventType, req, details = {}) => {
  try {
    const logData = {
      action: eventType,
      category: 'security',
      severity: getSeverityForSecurityEvent(eventType),
      status: details.success ? 'success' : 'failure',
      description: getDescriptionForSecurityEvent(eventType, details),
      metadata: {
        eventType: eventType,
        ...details
      },
      clientInfo: {
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent'),
        browser: parseBrowser(req.get('User-Agent')),
        os: parseOS(req.get('User-Agent'))
      },
      requestData: {
        method: req.method,
        url: req.originalUrl,
        headers: sanitizeHeaders(req.headers)
      }
    };
    
    if (req.user) {
      logData.user = req.user.id;
      logData.sessionInfo = {
        userId: req.user.id,
        walletAddress: req.user.walletAddress
      };
    }
    
    await AuditLog.createLog(logData);
  } catch (error) {
    console.error('Security event logging error:', error);
  }
};

/**
 * Blockchain event logger
 */
const logBlockchainEvent = async (eventType, req, blockchainData = {}) => {
  try {
    const logData = {
      action: eventType,
      category: 'verification',
      severity: 'info',
      status: 'success',
      description: `Blockchain event: ${eventType}`,
      metadata: {
        eventType: eventType
      },
      blockchainData: {
        network: blockchainData.network || 'sepolia',
        txHash: blockchainData.txHash,
        blockNumber: blockchainData.blockNumber,
        gasUsed: blockchainData.gasUsed,
        gasPrice: blockchainData.gasPrice,
        contractAddress: blockchainData.contractAddress,
        eventLogs: blockchainData.eventLogs
      },
      clientInfo: {
        ipAddress: getClientIP(req),
        userAgent: req.get('User-Agent')
      }
    };
    
    if (req.user) {
      logData.user = req.user.id;
    }
    
    if (req.issuer) {
      logData.issuer = req.issuer._id;
    }
    
    await AuditLog.createLog(logData);
  } catch (error) {
    console.error('Blockchain event logging error:', error);
  }
};

/**
 * Helper functions
 */
function generateCorrelationId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function shouldSkipLogging(path) {
  const skipPaths = [
    '/health',
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml'
  ];
  
  return skipPaths.some(skipPath => path.startsWith(skipPath));
}

function getClientIP(req) {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         '0.0.0.0';
}

function sanitizeHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return {};
  }
  
  const sanitized = { ...headers };
  
  // Remove sensitive headers
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token'
  ];
  
  sensitiveHeaders.forEach(header => {
    if (sanitized[header]) {
      sanitized[header] = '[REDACTED]';
    }
  });
  
  return sanitized;
}

function sanitizeRequestBody(body) {
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
    'secret'
  ];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
}

function sanitizeResponseBody(body) {
  if (!body || typeof body !== 'object') {
    return body;
  }
  
  // Don't log large response bodies
  const bodyString = JSON.stringify(body);
  if (bodyString.length > 10000) {
    return { message: '[LARGE_RESPONSE_BODY_TRUNCATED]', size: bodyString.length };
  }
  
  const sanitized = { ...body };
  
  // Remove sensitive fields from response
  if (sanitized.token) {
    sanitized.token = '[REDACTED]';
  }
  
  return sanitized;
}

function parseBrowser(userAgent) {
  if (!userAgent) return 'Unknown';
  
  if (userAgent.includes('Chrome')) return 'Chrome';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Safari')) return 'Safari';
  if (userAgent.includes('Edge')) return 'Edge';
  if (userAgent.includes('Opera')) return 'Opera';
  
  return 'Other';
}

function parseOS(userAgent) {
  if (!userAgent) return 'Unknown';
  
  if (userAgent.includes('Windows')) return 'Windows';
  if (userAgent.includes('Mac OS')) return 'macOS';
  if (userAgent.includes('Linux')) return 'Linux';
  if (userAgent.includes('Android')) return 'Android';
  if (userAgent.includes('iOS')) return 'iOS';
  
  return 'Other';
}

function getSeverityForSecurityEvent(eventType) {
  const severityMap = {
    'security_login_failed': 'warning',
    'security_registration_failed': 'warning',
    'security_account_locked': 'error',
    'security_password_reset': 'info',
    'security_password_change_failed': 'warning',
    'security_suspicious_activity': 'critical',
    'security_unauthorized_access': 'warning'
  };
  
  return severityMap[eventType] || 'info';
}

function getDescriptionForSecurityEvent(eventType, details) {
  const descriptions = {
    'security_login_failed': `Failed login attempt for ${details.username || 'unknown user'}`,
    'security_registration_failed': `Failed registration attempt: ${details.reason}`,
    'security_account_locked': `Account locked due to multiple failed attempts`,
    'security_password_reset': `Password reset requested`,
    'security_password_change_failed': `Failed password change attempt`,
    'security_suspicious_activity': `Suspicious activity detected: ${details.reason}`,
    'security_unauthorized_access': `Unauthorized access attempt to ${details.resource}`
  };
  
  return descriptions[eventType] || `Security event: ${eventType}`;
}

module.exports = {
  requestLogger,
  logSecurityEvent,
  logBlockchainEvent
};
