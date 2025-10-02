const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  issuer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Issuer'
  },
  
  credential: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Credential'
  },
  
  action: {
    type: String,
    required: [true, 'Action is required'],
    enum: [
      // User actions
      'user_register',
      'user_login',
      'user_logout',
      'user_update_profile',
      'user_change_password',
      'user_delete_account',
      
      // Issuer actions
      'issuer_register',
      'issuer_approve',
      'issuer_reject',
      'issuer_suspend',
      'issuer_reactivate',
      'issuer_update',
      
      // Credential actions
      'credential_issue',
      'credential_verify',
      'credential_revoke',
      'credential_suspend',
      'credential_reactivate',
      
      // System actions
      'system_backup',
      'system_restore',
      'system_maintenance',
      'system_error',
      
      // Security actions
      'security_login_failed',
      'security_account_locked',
      'security_password_reset',
      'security_suspicious_activity',
      
      // API actions
      'api_call',
      'api_error',
      'api_rate_limit'
    ]
  },
  
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: [
      'authentication',
      'authorization',
      'credential_management',
      'issuer_management',
      'user_management',
      'system',
      'security',
      'api',
      'verification'
    ]
  },
  
  severity: {
    type: String,
    enum: ['info', 'warning', 'error', 'critical'],
    default: 'info'
  },
  
  status: {
    type: String,
    enum: ['success', 'failure', 'pending', 'cancelled'],
    default: 'success'
  },
  
  description: {
    type: String,
    required: [true, 'Description is required'],
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  metadata: {
    type: Object,
    default: {}
  },
  
  requestData: {
    method: String,
    url: String,
    headers: Object,
    body: Object,
    query: Object,
    params: Object
  },
  
  responseData: {
    statusCode: Number,
    headers: Object,
    body: Object,
    responseTime: Number // in milliseconds
  },
  
  clientInfo: {
    ipAddress: {
      type: String,
      required: [true, 'IP address is required']
    },
    userAgent: String,
    browser: String,
    os: String,
    device: String,
    country: String,
    city: String
  },
  
  sessionInfo: {
    sessionId: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    walletAddress: String,
    loginTime: Date,
    lastActivity: Date
  },
  
  blockchainData: {
    network: String,
    txHash: String,
    blockNumber: Number,
    gasUsed: Number,
    gasPrice: String,
    contractAddress: String,
    eventLogs: [Object]
  },
  
  errorInfo: {
    errorCode: String,
    errorMessage: String,
    stackTrace: String,
    errorType: String
  },
  
  tags: [String],
  
  correlationId: {
    type: String,
    index: true
  },
  
  parentLogId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AuditLog'
  },
  
  isArchived: {
    type: Boolean,
    default: false
  },
  
  retentionDate: {
    type: Date,
    default: function() {
      // Default retention: 2 years
      const date = new Date();
      date.setFullYear(date.getFullYear() + 2);
      return date;
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance and querying
AuditLogSchema.index({ user: 1 });
AuditLogSchema.index({ issuer: 1 });
AuditLogSchema.index({ credential: 1 });
AuditLogSchema.index({ action: 1 });
AuditLogSchema.index({ category: 1 });
AuditLogSchema.index({ severity: 1 });
AuditLogSchema.index({ status: 1 });
AuditLogSchema.index({ createdAt: -1 });
AuditLogSchema.index({ correlationId: 1 });
AuditLogSchema.index({ 'clientInfo.ipAddress': 1 });
AuditLogSchema.index({ 'sessionInfo.userId': 1 });
AuditLogSchema.index({ 'blockchainData.txHash': 1 });
AuditLogSchema.index({ retentionDate: 1 });
AuditLogSchema.index({ isArchived: 1 });

// Compound indexes
AuditLogSchema.index({ user: 1, action: 1, createdAt: -1 });
AuditLogSchema.index({ category: 1, severity: 1, createdAt: -1 });
AuditLogSchema.index({ 'clientInfo.ipAddress': 1, createdAt: -1 });

// Virtual for log age
AuditLogSchema.virtual('ageInDays').get(function() {
  return Math.floor((new Date() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for checking if log should be archived
AuditLogSchema.virtual('shouldArchive').get(function() {
  return this.retentionDate < new Date();
});

// Static method to create audit log
AuditLogSchema.statics.createLog = function(logData) {
  const log = new this(logData);
  return log.save();
};

// Static method to find logs by user
AuditLogSchema.statics.findByUser = function(userId, limit = 50) {
  return this.find({ user: userId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('user', 'username email')
    .populate('issuer', 'name')
    .populate('credential', 'credentialType credentialHash');
};

// Static method to find logs by action
AuditLogSchema.statics.findByAction = function(action, limit = 100) {
  return this.find({ action: action })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Static method to find logs by IP address
AuditLogSchema.statics.findByIP = function(ipAddress, limit = 100) {
  return this.find({ 'clientInfo.ipAddress': ipAddress })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Static method to find security-related logs
AuditLogSchema.statics.findSecurityLogs = function(limit = 100) {
  return this.find({ 
    category: 'security',
    severity: { $in: ['warning', 'error', 'critical'] }
  })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Static method to find failed login attempts
AuditLogSchema.statics.findFailedLogins = function(timeWindow = 24) {
  const since = new Date();
  since.setHours(since.getHours() - timeWindow);
  
  return this.find({
    action: 'security_login_failed',
    createdAt: { $gte: since }
  })
    .sort({ createdAt: -1 });
};

// Static method to get statistics
AuditLogSchema.statics.getStatistics = function(timeWindow = 24) {
  const since = new Date();
  since.setHours(since.getHours() - timeWindow);
  
  return this.aggregate([
    { $match: { createdAt: { $gte: since } } },
    {
      $group: {
        _id: {
          action: '$action',
          status: '$status'
        },
        count: { $sum: 1 }
      }
    },
    {
      $group: {
        _id: '$_id.action',
        total: { $sum: '$count' },
        success: {
          $sum: {
            $cond: [{ $eq: ['$_id.status', 'success'] }, '$count', 0]
          }
        },
        failure: {
          $sum: {
            $cond: [{ $eq: ['$_id.status', 'failure'] }, '$count', 0]
          }
        }
      }
    },
    { $sort: { total: -1 } }
  ]);
};

// Static method to archive old logs
AuditLogSchema.statics.archiveOldLogs = function() {
  return this.updateMany(
    { 
      retentionDate: { $lt: new Date() },
      isArchived: false 
    },
    { 
      $set: { isArchived: true } 
    }
  );
};

// Static method to delete archived logs
AuditLogSchema.statics.deleteArchivedLogs = function(olderThanDays = 30) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);
  
  return this.deleteMany({
    isArchived: true,
    updatedAt: { $lt: cutoffDate }
  });
};

// Method to add correlation ID for tracking related logs
AuditLogSchema.methods.setCorrelationId = function(correlationId) {
  this.correlationId = correlationId;
  return this.save();
};

// Method to link to parent log
AuditLogSchema.methods.setParent = function(parentLogId) {
  this.parentLogId = parentLogId;
  return this.save();
};

// Pre-save middleware to set default values
AuditLogSchema.pre('save', function(next) {
  // Generate correlation ID if not provided
  if (!this.correlationId && this.isNew) {
    this.correlationId = new mongoose.Types.ObjectId().toString();
  }
  
  // Set retention date based on severity
  if (this.isNew && !this.retentionDate) {
    const date = new Date();
    switch (this.severity) {
      case 'critical':
        date.setFullYear(date.getFullYear() + 7); // 7 years
        break;
      case 'error':
        date.setFullYear(date.getFullYear() + 3); // 3 years
        break;
      case 'warning':
        date.setFullYear(date.getFullYear() + 2); // 2 years
        break;
      default:
        date.setFullYear(date.getFullYear() + 1); // 1 year
    }
    this.retentionDate = date;
  }
  
  next();
});

module.exports = mongoose.model('AuditLog', AuditLogSchema);
