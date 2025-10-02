const mongoose = require('mongoose');

const CredentialSchema = new mongoose.Schema({
  issuer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Issuer',
    required: [true, 'Issuer reference is required']
  },
  
  subject: {
    type: String,
    required: [true, 'Subject identifier is required'],
    trim: true,
    maxlength: [200, 'Subject identifier cannot exceed 200 characters']
  },
  
  subjectAddress: {
    type: String,
    trim: true,
    match: [/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address format']
  },
  
  credentialType: {
    type: String,
    required: [true, 'Credential type is required'],
    enum: [
      'IdentityCredential',
      'EducationalCredential',
      'ProfessionalCredential',
      'HealthCredential',
      'FinancialCredential',
      'GovernmentCredential',
      'CustomCredential'
    ]
  },
  
  vc: {
    type: Object,
    required: [true, 'Verifiable Credential data is required'],
    validate: {
      validator: function(v) {
        // Basic VC structure validation
        return v && 
               v['@context'] && 
               v.type && 
               v.issuer && 
               v.credentialSubject &&
               v.issuanceDate;
      },
      message: 'Invalid Verifiable Credential structure'
    }
  },
  
  ipfsHash: {
    type: String,
    required: [true, 'IPFS hash is required'],
    trim: true,
    match: [/^Qm[1-9A-HJ-NP-Za-km-z]{44}$|^baf[a-z0-9]{56}$/, 'Invalid IPFS hash format']
  },
  
  credentialHash: {
    type: String,
    required: [true, 'Credential hash is required'],
    unique: true,
    trim: true,
    match: [/^0x[a-fA-F0-9]{64}$/, 'Invalid credential hash format']
  },
  
  status: {
    type: String,
    enum: {
      values: ['valid', 'revoked', 'suspended', 'expired'],
      message: 'Status must be one of: valid, revoked, suspended, expired'
    },
    default: 'valid'
  },
  
  expirationDate: {
    type: Date,
    validate: {
      validator: function(v) {
        return !v || v > this.createdAt;
      },
      message: 'Expiration date must be after issuance date'
    }
  },
  
  revocationData: {
    revokedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    revokedAt: Date,
    revocationReason: {
      type: String,
      enum: [
        'compromised',
        'superseded',
        'cessation_of_operation',
        'certificate_hold',
        'privilege_withdrawn',
        'aa_compromise',
        'unspecified'
      ]
    },
    revocationTxHash: String,
    revocationBlockNumber: Number
  },
  
  verificationData: {
    totalVerifications: {
      type: Number,
      default: 0,
      min: 0
    },
    lastVerificationDate: Date,
    verificationHistory: [{
      verifier: String,
      verifiedAt: {
        type: Date,
        default: Date.now
      },
      verificationResult: {
        type: String,
        enum: ['valid', 'invalid', 'expired', 'revoked']
      },
      ipAddress: String,
      userAgent: String
    }]
  },
  
  metadata: {
    tags: [String],
    category: String,
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    confidentialityLevel: {
      type: String,
      enum: ['public', 'internal', 'confidential', 'restricted'],
      default: 'internal'
    },
    dataRetentionPeriod: {
      type: Number, // in days
      default: 365
    }
  },
  
  proofData: {
    type: {
      type: String,
      default: 'EcdsaSecp256k1Signature2019'
    },
    created: {
      type: Date,
      default: Date.now
    },
    proofPurpose: {
      type: String,
      default: 'assertionMethod'
    },
    verificationMethod: String,
    jws: String, // JSON Web Signature
    signature: String // Raw signature
  },
  
  auditTrail: [{
    action: {
      type: String,
      enum: ['issued', 'verified', 'revoked', 'suspended', 'reactivated', 'updated'],
      required: true
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    details: Object,
    ipAddress: String,
    userAgent: String
  }],
  
  schemaVersion: {
    type: String,
    default: '1.0'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
CredentialSchema.index({ issuer: 1 });
CredentialSchema.index({ subject: 1 });
CredentialSchema.index({ subjectAddress: 1 });
CredentialSchema.index({ credentialHash: 1 });
CredentialSchema.index({ status: 1 });
CredentialSchema.index({ credentialType: 1 });
CredentialSchema.index({ createdAt: -1 });
CredentialSchema.index({ expirationDate: 1 });
CredentialSchema.index({ 'verificationData.totalVerifications': -1 });

// Compound indexes
CredentialSchema.index({ issuer: 1, status: 1 });
CredentialSchema.index({ subject: 1, status: 1 });
CredentialSchema.index({ credentialType: 1, status: 1 });

// Virtual for checking if credential is expired
CredentialSchema.virtual('isExpired').get(function() {
  return this.expirationDate && this.expirationDate < new Date();
});

// Virtual for checking if credential is currently valid
CredentialSchema.virtual('isCurrentlyValid').get(function() {
  return this.status === 'valid' && !this.isExpired;
});

// Virtual for age in days
CredentialSchema.virtual('ageInDays').get(function() {
  return Math.floor((new Date() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Method to revoke credential
CredentialSchema.methods.revoke = function(revokedBy, reason, txHash, blockNumber) {
  this.status = 'revoked';
  this.revocationData = {
    revokedBy: revokedBy,
    revokedAt: new Date(),
    revocationReason: reason || 'unspecified',
    revocationTxHash: txHash,
    revocationBlockNumber: blockNumber
  };
  
  this.auditTrail.push({
    action: 'revoked',
    performedBy: revokedBy,
    details: {
      reason: reason,
      txHash: txHash,
      blockNumber: blockNumber
    }
  });
  
  return this.save();
};

// Method to record verification
CredentialSchema.methods.recordVerification = function(verifier, result, ipAddress, userAgent) {
  this.verificationData.totalVerifications += 1;
  this.verificationData.lastVerificationDate = new Date();
  
  this.verificationData.verificationHistory.push({
    verifier: verifier,
    verificationResult: result,
    ipAddress: ipAddress,
    userAgent: userAgent
  });
  
  // Keep only last 100 verification records
  if (this.verificationData.verificationHistory.length > 100) {
    this.verificationData.verificationHistory = this.verificationData.verificationHistory.slice(-100);
  }
  
  this.auditTrail.push({
    action: 'verified',
    details: {
      verifier: verifier,
      result: result,
      ipAddress: ipAddress
    }
  });
  
  return this.save();
};

// Method to add audit trail entry
CredentialSchema.methods.addAuditEntry = function(action, performedBy, details, ipAddress, userAgent) {
  this.auditTrail.push({
    action: action,
    performedBy: performedBy,
    details: details,
    ipAddress: ipAddress,
    userAgent: userAgent
  });
  
  return this.save();
};

// Static method to find by credential hash
CredentialSchema.statics.findByHash = function(hash) {
  return this.findOne({ credentialHash: hash });
};

// Static method to find valid credentials
CredentialSchema.statics.findValid = function() {
  return this.find({ 
    status: 'valid',
    $or: [
      { expirationDate: { $exists: false } },
      { expirationDate: { $gt: new Date() } }
    ]
  });
};

// Static method to find expired credentials
CredentialSchema.statics.findExpired = function() {
  return this.find({ 
    expirationDate: { $lt: new Date() },
    status: { $ne: 'revoked' }
  });
};

// Static method to find credentials by issuer
CredentialSchema.statics.findByIssuer = function(issuerId) {
  return this.find({ issuer: issuerId });
};

// Static method to find credentials by subject
CredentialSchema.statics.findBySubject = function(subject) {
  return this.find({ subject: subject });
};

// Pre-save middleware to update audit trail
CredentialSchema.pre('save', function(next) {
  if (this.isNew) {
    this.auditTrail.push({
      action: 'issued',
      timestamp: new Date(),
      details: {
        credentialType: this.credentialType,
        ipfsHash: this.ipfsHash
      }
    });
  }
  next();
});

// Pre-save middleware to handle expiration
CredentialSchema.pre('save', function(next) {
  if (this.expirationDate && this.expirationDate < new Date() && this.status === 'valid') {
    this.status = 'expired';
  }
  next();
});

module.exports = mongoose.model('Credential', CredentialSchema);
