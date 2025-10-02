const mongoose = require('mongoose');

const IssuerSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User reference is required'],
    unique: true
  },
  
  name: {
    type: String,
    required: [true, 'Issuer name is required'],
    trim: true,
    minlength: [2, 'Issuer name must be at least 2 characters long'],
    maxlength: [100, 'Issuer name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  website: {
    type: String,
    trim: true,
    match: [/^https?:\/\/.+/, 'Website must be a valid URL']
  },
  
  logo: {
    type: String,
    trim: true
  },
  
  metadataUri: {
    type: String,
    required: [true, 'Metadata URI is required'],
    trim: true,
    match: [/^ipfs:\/\/.+/, 'Metadata URI must be a valid IPFS URI']
  },
  
  blockchainAddress: {
    type: String,
    required: [true, 'Blockchain address is required'],
    trim: true,
    match: [/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address format']
  },
  
  status: {
    type: String,
    enum: {
      values: ['pending', 'active', 'suspended', 'rejected'],
      message: 'Status must be one of: pending, active, suspended, rejected'
    },
    default: 'pending'
  },
  
  verificationLevel: {
    type: String,
    enum: {
      values: ['basic', 'verified', 'premium'],
      message: 'Verification level must be one of: basic, verified, premium'
    },
    default: 'basic'
  },
  
  capabilities: [{
    type: String,
    enum: [
      'identity_verification',
      'educational_credentials',
      'professional_certifications',
      'health_records',
      'financial_verification',
      'government_id',
      'custom'
    ]
  }],
  
  contactInfo: {
    email: {
      type: String,
      trim: true,
      lowercase: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
      type: String,
      trim: true
    },
    address: {
      street: String,
      city: String,
      state: String,
      country: String,
      postalCode: String
    }
  },
  
  registrationData: {
    businessRegistration: String,
    taxId: String,
    licenseNumber: String,
    regulatoryBody: String
  },
  
  statistics: {
    credentialsIssued: {
      type: Number,
      default: 0,
      min: 0
    },
    credentialsRevoked: {
      type: Number,
      default: 0,
      min: 0
    },
    lastIssuanceDate: Date,
    totalVerifications: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  
  settings: {
    autoApproveCredentials: {
      type: Boolean,
      default: false
    },
    allowBulkIssuance: {
      type: Boolean,
      default: false
    },
    maxCredentialsPerDay: {
      type: Number,
      default: 100,
      min: 1,
      max: 10000
    },
    notificationPreferences: {
      email: {
        type: Boolean,
        default: true
      },
      webhook: {
        type: Boolean,
        default: false
      },
      webhookUrl: String
    }
  },
  
  onChainData: {
    registrationTxHash: String,
    registrationBlockNumber: Number,
    lastUpdateTxHash: String,
    lastUpdateBlockNumber: Number,
    isOnChainRegistered: {
      type: Boolean,
      default: false
    }
  },
  
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  approvedAt: Date,
  
  suspendedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  suspendedAt: Date,
  
  suspensionReason: String,
  
  notes: [{
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    content: {
      type: String,
      required: true,
      maxlength: 1000
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
IssuerSchema.index({ user: 1 });
IssuerSchema.index({ blockchainAddress: 1 });
IssuerSchema.index({ status: 1 });
IssuerSchema.index({ verificationLevel: 1 });
IssuerSchema.index({ createdAt: -1 });
IssuerSchema.index({ 'statistics.credentialsIssued': -1 });

// Virtual for issuer reputation score
IssuerSchema.virtual('reputationScore').get(function() {
  const issued = this.statistics.credentialsIssued || 0;
  const revoked = this.statistics.credentialsRevoked || 0;
  
  if (issued === 0) return 0;
  
  const revokedRatio = revoked / issued;
  let score = 100 - (revokedRatio * 50); // Base score reduction for revocations
  
  // Bonus for verification level
  if (this.verificationLevel === 'premium') score += 10;
  else if (this.verificationLevel === 'verified') score += 5;
  
  // Bonus for volume (diminishing returns)
  score += Math.min(Math.log10(issued + 1) * 5, 20);
  
  return Math.max(0, Math.min(100, Math.round(score)));
});

// Virtual for active status
IssuerSchema.virtual('isActive').get(function() {
  return this.status === 'active';
});

// Method to increment credentials issued
IssuerSchema.methods.incrementCredentialsIssued = function() {
  this.statistics.credentialsIssued += 1;
  this.statistics.lastIssuanceDate = new Date();
  return this.save();
};

// Method to increment credentials revoked
IssuerSchema.methods.incrementCredentialsRevoked = function() {
  this.statistics.credentialsRevoked += 1;
  return this.save();
};

// Method to add note
IssuerSchema.methods.addNote = function(authorId, content) {
  this.notes.push({
    author: authorId,
    content: content
  });
  return this.save();
};

// Method to check if issuer can issue credentials
IssuerSchema.methods.canIssueCredentials = function() {
  return this.status === 'active' && this.onChainData.isOnChainRegistered;
};

// Static method to find by blockchain address
IssuerSchema.statics.findByAddress = function(address) {
  return this.findOne({ blockchainAddress: address });
};

// Static method to find active issuers
IssuerSchema.statics.findActive = function() {
  return this.find({ status: 'active' });
};

// Static method to find pending issuers
IssuerSchema.statics.findPending = function() {
  return this.find({ status: 'pending' });
};

// Pre-save middleware to validate capabilities
IssuerSchema.pre('save', function(next) {
  // Ensure at least one capability is selected
  if (this.capabilities.length === 0) {
    this.capabilities.push('identity_verification');
  }
  next();
});

module.exports = mongoose.model('Issuer', IssuerSchema);
