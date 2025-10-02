# SSI System Setup Guide

This guide will help you set up and run the complete SSI (Self-Sovereign Identity) system locally.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v16 or higher) - [Download here](https://nodejs.org/)
- **npm** or **yarn** package manager
- **Docker** and **Docker Compose** - [Download here](https://docker.com/)
- **MetaMask** browser extension - [Install here](https://metamask.io/)
- **Git** - [Download here](https://git-scm.com/)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd SSI
```

### 2. Environment Setup

#### Backend Environment
```bash
cd backend
cp env.example .env
```

Edit `backend/.env` with your configuration:
```env
# Database
MONGO_URI=mongodb://localhost:27017/ssi

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Pinata IPFS
PINATA_KEY=your-pinata-api-key
PINATA_SECRET=your-pinata-secret-key

# Ethereum
CONTRACT_ADDRESS=0xB2e56C41FA91232FfF4d41D2fbc71340C537d49E
SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
```

#### Frontend Environment
```bash
cd ../frontend
cp env.example .env
```

Edit `frontend/.env`:
```env
REACT_APP_API_URL=http://localhost:4000
REACT_APP_CONTRACT_ADDRESS=0xB2e56C41FA91232FfF4d41D2fbc71340C537d49E
REACT_APP_SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
```

### 3. Install Dependencies

```bash
# Backend dependencies
cd backend
npm install

# Frontend dependencies
cd ../frontend
npm install
```

### 4. Start Services

#### Option A: Using Docker (Recommended)
```bash
# From project root
docker-compose up -d
```

This starts:
- MongoDB database
- Backend API server
- Frontend React app
- MongoDB Express (database admin)

#### Option B: Manual Setup

**Start MongoDB:**
```bash
docker-compose up -d mongodb
```

**Start Backend:**
```bash
cd backend
npm run dev
```

**Start Frontend (new terminal):**
```bash
cd frontend
npm start
```

### 5. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:4000
- **MongoDB Express**: http://localhost:8081 (admin/admin123)

## 🔧 Configuration Details

### Required Services

#### 1. Pinata IPFS Setup
1. Create account at [Pinata.cloud](https://pinata.cloud/)
2. Generate API keys in dashboard
3. Add keys to backend `.env` file

#### 2. Infura Ethereum RPC
1. Create account at [Infura.io](https://infura.io/)
2. Create new project for Ethereum
3. Copy Sepolia endpoint URL
4. Add to both backend and frontend `.env` files

#### 3. MetaMask Setup
1. Install MetaMask browser extension
2. Create or import wallet
3. Add Sepolia testnet:
   - Network Name: Sepolia Testnet
   - RPC URL: https://rpc.sepolia.org
   - Chain ID: 11155111
   - Currency Symbol: SEP
   - Block Explorer: https://sepolia.etherscan.io

#### 4. Get Sepolia Test ETH
- Use [Sepolia Faucet](https://sepoliafaucet.com/)
- Or [Alchemy Faucet](https://sepoliafaucet.com/)

## 📦 Smart Contract Deployment

The contract is already deployed at `0xB2e56C41FA91232FfF4d41D2fbc71340C537d49E`, but if you want to deploy your own:

### 1. Using Remix IDE

1. Open [Remix IDE](https://remix.ethereum.org/)
2. Create new file: `IssuerRegistry.sol`
3. Copy contract code from `contracts/IssuerRegistry.sol`
4. Compile with Solidity 0.8.17+
5. Deploy to Sepolia testnet using MetaMask
6. Copy deployed contract address
7. Update address in both `.env` files

### 2. Contract Verification (Optional)

1. Go to [Sepolia Etherscan](https://sepolia.etherscan.io/)
2. Search for your contract address
3. Click "Verify and Publish"
4. Upload source code and verify

## 🧪 Testing the System

### 1. Create User Account
1. Go to http://localhost:3000
2. Click "Get Started" or "Sign Up"
3. Fill registration form
4. Connect MetaMask wallet (optional)
5. Complete registration

### 2. Login
1. Use credentials to sign in
2. Connect MetaMask if not done during registration

### 3. Become an Issuer
1. From dashboard, click "Become an Issuer"
2. Fill issuer registration form
3. Complete MetaMask transaction to register on-chain
4. Confirm registration in backend

### 4. Issue Credentials
1. Go to Issuer Dashboard
2. Click "Issue Credential"
3. Fill credential details
4. Sign with MetaMask
5. Credential stored on IPFS and database

### 5. Verify Credentials
1. Go to "Verify Credential" page
2. Enter credential hash or upload credential
3. System verifies signature, issuer status, and revocation

## 🔍 Troubleshooting

### Common Issues

#### 1. MetaMask Connection Issues
- Ensure MetaMask is unlocked
- Check you're on Sepolia testnet
- Refresh page and try reconnecting

#### 2. Transaction Failures
- Ensure sufficient Sepolia ETH for gas
- Check gas limit settings
- Verify contract address is correct

#### 3. API Connection Issues
- Check backend server is running on port 4000
- Verify CORS settings allow frontend domain
- Check network connectivity

#### 4. Database Issues
- Ensure MongoDB is running
- Check connection string in `.env`
- Verify database permissions

#### 5. IPFS Issues
- Verify Pinata API keys are correct
- Check Pinata account limits
- Test IPFS gateway accessibility

### Debug Mode

Enable debug logging:

**Backend:**
```env
LOG_LEVEL=debug
NODE_ENV=development
```

**Frontend:**
```env
REACT_APP_ENABLE_DEBUG=true
```

### Health Checks

Check service status:

```bash
# Backend health
curl http://localhost:4000/health

# Database connection
docker-compose logs mongodb

# Frontend build
cd frontend && npm run build
```

## 📚 Development Workflow

### 1. Backend Development
```bash
cd backend
npm run dev  # Starts with nodemon for auto-reload
```

### 2. Frontend Development
```bash
cd frontend
npm start    # Starts development server with hot reload
```

### 3. Database Management
```bash
# View database
open http://localhost:8081

# Reset database
docker-compose down -v
docker-compose up -d mongodb
```

### 4. Testing
```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test
```

## 🚀 Production Deployment

### Environment Variables
Update production values:
- Use strong JWT secrets
- Use production MongoDB (Atlas recommended)
- Use production-grade IPFS service
- Enable HTTPS
- Set proper CORS origins

### Security Checklist
- [ ] Change all default passwords
- [ ] Use environment-specific secrets
- [ ] Enable HTTPS/SSL
- [ ] Configure proper CORS
- [ ] Set up monitoring and logging
- [ ] Regular security updates
- [ ] Backup strategy for database

### Deployment Options
- **Frontend**: Netlify, Vercel, AWS S3 + CloudFront
- **Backend**: Heroku, AWS ECS, DigitalOcean App Platform
- **Database**: MongoDB Atlas, AWS DocumentDB

## 📞 Support

If you encounter issues:

1. Check this setup guide
2. Review error logs in console
3. Check GitHub issues
4. Create new issue with:
   - Error message
   - Steps to reproduce
   - Environment details
   - Browser/OS information

## 🎯 Next Steps

After successful setup:

1. Explore the dashboard
2. Register as an issuer
3. Issue test credentials
4. Verify credentials
5. Check blockchain transactions on Etherscan
6. Review IPFS data on Pinata

Happy building with SSI! 🎉
