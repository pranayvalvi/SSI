# Security Guidelines

## Critical Security Issues Fixed

### 1. Hardcoded Credentials
- **Issue**: Hardcoded passwords and API keys in source code
- **Fix**: Use environment variables for all sensitive data
- **Action**: Update `.env` files with secure values before deployment

### 2. Ethers.js Compatibility
- **Issue**: Using v5 syntax with v6 library causing runtime errors
- **Fix**: Updated all BigNumber operations and gas estimation calls
- **Action**: Test all blockchain interactions thoroughly

### 3. Package Vulnerabilities
- **Issue**: Multiple npm packages with known security vulnerabilities
- **Fix**: Run `npm audit fix` in all directories
- **Action**: Regularly update dependencies

### 4. CSRF Protection
- **Issue**: API endpoints vulnerable to Cross-Site Request Forgery
- **Fix**: Added CSRF middleware (optional implementation)
- **Action**: Implement CSRF tokens for state-changing operations

## Environment Variables Required

### Backend (.env)
```
MONGO_URI=mongodb://localhost:27017/ssi
JWT_SECRET=your-secure-jwt-secret-here
PINATA_JWT=your-pinata-jwt-token
CONTRACT_ADDRESS=0xYourDeployedContractAddress
SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_INFURA_KEY
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD_HASH=your-bcrypt-hashed-password
MONGO_APP_USER=ssi_app
MONGO_APP_PASSWORD=your-secure-mongo-password
```

### Frontend (.env)
```
REACT_APP_API_URL=http://localhost:4000
REACT_APP_CONTRACT_ADDRESS=0xYourDeployedContractAddress
REACT_APP_SEPOLIA_RPC=https://sepolia.infura.io/v3/YOUR_INFURA_KEY
REACT_APP_STORAGE_PREFIX=ssi_prod
```

## Deployment Checklist

- [ ] Update all environment variables with production values
- [ ] Deploy smart contract to Sepolia testnet
- [ ] Run `npm audit fix` in all directories
- [ ] Enable HTTPS in production
- [ ] Set up proper CORS origins
- [ ] Configure rate limiting
- [ ] Set up monitoring and logging
- [ ] Test all critical paths
- [ ] Backup database regularly

## Security Best Practices

1. **Never commit sensitive data** to version control
2. **Use HTTPS** for all production traffic
3. **Validate all inputs** on both client and server
4. **Implement proper authentication** and authorization
5. **Keep dependencies updated** regularly
6. **Monitor for security vulnerabilities**
7. **Use secure password hashing** (bcrypt with high rounds)
8. **Implement rate limiting** to prevent abuse
9. **Log security events** for monitoring
10. **Regular security audits** of code and infrastructure