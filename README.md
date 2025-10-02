# Blockchain-based Digital Identity Verification (SSI) System

A complete Self-Sovereign Identity (SSI) system built with **Remix + Solidity (Sepolia) + MetaMask + MongoDB + Pinata + React**.

## 🎯 Project Overview

This system enables:
- **User Registration & Authentication** (MongoDB)
- **Issuer Registration** (on-chain + IPFS metadata)
- **Verifiable Credential Issuance** (signed VCs with IPFS storage)
- **Credential Verification** (signature + issuer + revocation checks)
- **Credential Revocation** (on-chain + database)

## 🏗️ Architecture

```
[React SPA] <--> [Express API] <--> [MongoDB]
     |              |                   
     |              └--> [Pinata/IPFS]  
     |                                  
  MetaMask <--> Ethereum Sepolia <-- [IssuerRegistry Contract]
```

## 🚀 Quick Start

### Prerequisites
- Node.js 16+
- MongoDB (local or Atlas)
- MetaMask browser extension
- Pinata account (IPFS)
- Sepolia testnet ETH

### 1. Clone & Install
```bash
git clone <your-repo>
cd SSI
npm install
cd frontend && npm install
cd ../backend && npm install
```

### 2. Environment Setup
Copy `.env.example` to `.env` and fill in your values:
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

### 3. Deploy Smart Contract
1. Open `contracts/IssuerRegistry.sol` in [Remix IDE](https://remix.ethereum.org)
2. Compile with Solidity 0.8.17+
3. Deploy to Sepolia testnet
4. Copy contract address to your `.env` files

### 4. Start Services
```bash
# Start MongoDB (if local)
docker-compose up -d

# Start backend
cd backend && npm run dev

# Start frontend (new terminal)
cd frontend && npm start
```

## 📁 Project Structure

```
SSI/
├── contracts/
│   └── IssuerRegistry.sol          # Smart contract for Remix
├── backend/
│   ├── models/                     # MongoDB schemas
│   ├── routes/                     # API endpoints
│   ├── utils/                      # Helpers (Pinata, etc.)
│   ├── server.js                   # Express app entry
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/             # React components
│   │   ├── utils/                  # Web3 helpers
│   │   ├── pages/                  # Main pages
│   │   └── App.js
│   └── package.json
├── docker-compose.yml              # MongoDB for development
└── README.md
```

## 🔧 Key Features

### Smart Contract (Sepolia)
- **Issuer Registration**: On-chain issuer registry with IPFS metadata
- **Credential Revocation**: Tamper-proof revocation tracking
- **Access Control**: Owner-based permissions

### Backend API
- **Authentication**: JWT-based user auth
- **Issuer Management**: Register issuers with IPFS metadata
- **Credential Lifecycle**: Issue, store, and revoke credentials
- **IPFS Integration**: Pinata for decentralized storage

### Frontend (React)
- **MetaMask Integration**: Web3 wallet connection
- **Issuer Onboarding**: Register as credential issuer
- **Credential Issuance**: Create and sign verifiable credentials
- **Verification Flow**: Present and verify credentials

## 🔐 Security Features

- **Digital Signatures**: ECDSA signatures for credential integrity
- **On-chain Verification**: Blockchain-based issuer validation
- **Revocation Checking**: Real-time credential status verification
- **Decentralized Storage**: IPFS for censorship-resistant metadata

## 🧪 Testing

```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test

# Smart contract tests (in Remix)
# Use Remix IDE testing framework
```

## 🚀 Deployment

### Smart Contract
1. Deploy `IssuerRegistry.sol` to Sepolia via Remix
2. Verify contract on Etherscan
3. Update contract address in environment files

### Backend
```bash
# Production deployment (example with PM2)
npm install -g pm2
cd backend
pm2 start server.js --name ssi-backend
```

### Frontend
```bash
cd frontend
npm run build
# Deploy build/ to your hosting service
```

## 📚 API Documentation

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login

### Issuers
- `POST /api/issuers/register` - Register as issuer
- `GET /api/issuers` - List registered issuers

### Credentials
- `POST /api/credentials/issue` - Issue new credential
- `POST /api/credentials/verify` - Verify credential
- `POST /api/credentials/revoke` - Revoke credential

## 🔧 Environment Variables

### Backend (.env)
```
MONGO_URI=mongodb://localhost:27017/ssi
JWT_SECRET=your-jwt-secret
PINATA_KEY=your-pinata-key
PINATA_SECRET=your-pinata-secret
CONTRACT_ADDRESS=0x...
PORT=4000
```

### Frontend (.env)
```
REACT_APP_API_URL=http://localhost:4000
REACT_APP_CONTRACT_ADDRESS=0x...
REACT_APP_SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_KEY
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For questions and support:
- Create an issue on GitHub
- Check the documentation
- Review the example flows in `/docs`

---

**Built with ❤️ for the decentralized future**
