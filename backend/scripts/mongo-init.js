// MongoDB initialization script
// This script runs when the MongoDB container starts for the first time

// Switch to the SSI database
db = db.getSiblingDB('ssi');

// Create application user
db.createUser({
  user: 'ssi_app',
  pwd: 'ssi_password_123',
  roles: [
    {
      role: 'readWrite',
      db: 'ssi'
    }
  ]
});

// Create collections with validation
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['username', 'email', 'passwordHash'],
      properties: {
        username: {
          bsonType: 'string',
          minLength: 3,
          maxLength: 50
        },
        email: {
          bsonType: 'string',
          pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        },
        passwordHash: {
          bsonType: 'string'
        },
        walletAddress: {
          bsonType: 'string',
          pattern: '^0x[a-fA-F0-9]{40}$'
        },
        role: {
          bsonType: 'string',
          enum: ['user', 'issuer', 'verifier', 'admin']
        }
      }
    }
  }
});

db.createCollection('issuers', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['user', 'name', 'metadataUri', 'blockchainAddress'],
      properties: {
        name: {
          bsonType: 'string',
          minLength: 2,
          maxLength: 100
        },
        metadataUri: {
          bsonType: 'string',
          pattern: '^ipfs://.+'
        },
        blockchainAddress: {
          bsonType: 'string',
          pattern: '^0x[a-fA-F0-9]{40}$'
        },
        status: {
          bsonType: 'string',
          enum: ['pending', 'active', 'suspended', 'rejected']
        }
      }
    }
  }
});

db.createCollection('credentials', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['issuer', 'subject', 'credentialType', 'vc', 'ipfsHash', 'credentialHash'],
      properties: {
        credentialType: {
          bsonType: 'string',
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
        credentialHash: {
          bsonType: 'string',
          pattern: '^0x[a-fA-F0-9]{64}$'
        },
        status: {
          bsonType: 'string',
          enum: ['valid', 'revoked', 'suspended', 'expired']
        }
      }
    }
  }
});

// Create indexes for performance
db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ walletAddress: 1 }, { sparse: true });

db.issuers.createIndex({ user: 1 }, { unique: true });
db.issuers.createIndex({ blockchainAddress: 1 }, { unique: true });
db.issuers.createIndex({ status: 1 });

db.credentials.createIndex({ credentialHash: 1 }, { unique: true });
db.credentials.createIndex({ issuer: 1 });
db.credentials.createIndex({ subject: 1 });
db.credentials.createIndex({ status: 1 });
db.credentials.createIndex({ credentialType: 1 });
db.credentials.createIndex({ createdAt: -1 });

db.auditlogs.createIndex({ user: 1 });
db.auditlogs.createIndex({ action: 1 });
db.auditlogs.createIndex({ category: 1 });
db.auditlogs.createIndex({ createdAt: -1 });
db.auditlogs.createIndex({ 'clientInfo.ipAddress': 1 });

// Insert sample admin user (password: admin123)
db.users.insertOne({
  username: 'admin',
  email: 'admin@ssi-system.com',
  passwordHash: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4.6YOqK8Pu', // admin123
  role: 'admin',
  isActive: true,
  isEmailVerified: true,
  profile: {
    firstName: 'System',
    lastName: 'Administrator',
    organization: 'SSI System'
  },
  createdAt: new Date(),
  updatedAt: new Date()
});

print('✅ SSI Database initialized successfully');
print('📊 Collections created: users, issuers, credentials, auditlogs');
print('🔐 Admin user created: admin / admin123');
print('📈 Indexes created for optimal performance');
