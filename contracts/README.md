# Smart Contract Deployment Guide

## IssuerRegistry.sol

This contract manages verifiable credential issuers and credential revocation on the Ethereum blockchain.

### Features

- **Issuer Registration**: Register credential issuers with IPFS metadata
- **Credential Revocation**: Track revoked credentials on-chain
- **Access Control**: Owner-based permissions and issuer validation
- **Batch Operations**: Efficiently revoke multiple credentials
- **Metadata Management**: IPFS-based issuer information storage

### Deployment Steps (Remix IDE)

1. **Open Remix IDE**: Go to [remix.ethereum.org](https://remix.ethereum.org)

2. **Create Contract File**:
   - Create new file: `IssuerRegistry.sol`
   - Copy the contract code from this directory

3. **Compile Contract**:
   - Go to "Solidity Compiler" tab
   - Select compiler version: `0.8.17` or higher
   - Click "Compile IssuerRegistry.sol"

4. **Deploy to Sepolia**:
   - Go to "Deploy & Run Transactions" tab
   - Environment: "Injected Provider - MetaMask"
   - Ensure MetaMask is connected to Sepolia testnet
   - Select contract: `IssuerRegistry`
   - Click "Deploy"
   - Confirm transaction in MetaMask

5. **Verify Contract** (Optional but recommended):
   - Copy deployed contract address
   - Go to [sepolia.etherscan.io](https://sepolia.etherscan.io)
   - Search for your contract address
   - Click "Verify and Publish"
   - Upload source code and constructor parameters

### Contract Functions

#### Public Functions

- `registerIssuer(address, string)` - Register new issuer with metadata
- `updateIssuer(address, string)` - Update issuer metadata
- `revokeCredential(bytes32)` - Revoke a single credential
- `batchRevokeCredentials(bytes32[])` - Revoke multiple credentials

#### View Functions

- `isIssuerRegistered(address)` - Check if address is registered issuer
- `isCredentialRevoked(bytes32)` - Check if credential is revoked
- `getIssuerMetadata(address)` - Get issuer IPFS metadata URI
- `getIssuer(address)` - Get complete issuer information
- `getIssuerCount()` - Get total number of issuers

#### Owner Functions

- `setIssuerStatus(address, bool)` - Activate/deactivate issuer
- `transferOwnership(address)` - Transfer contract ownership

### Events

- `IssuerRegistered` - Emitted when new issuer registers
- `IssuerUpdated` - Emitted when issuer updates metadata
- `IssuerStatusChanged` - Emitted when issuer status changes
- `CredentialRevoked` - Emitted when credential is revoked
- `OwnershipTransferred` - Emitted when ownership changes

### Gas Estimates

- Deploy: ~1,200,000 gas
- Register Issuer: ~100,000 gas
- Revoke Credential: ~50,000 gas
- Batch Revoke (10 creds): ~200,000 gas

### Security Considerations

1. **Access Control**: Only registered issuers can revoke credentials
2. **Input Validation**: All inputs are validated for security
3. **Reentrancy**: No external calls, safe from reentrancy attacks
4. **Integer Overflow**: Using Solidity 0.8+ with built-in overflow protection

### Integration with Backend

After deployment, update your backend `.env` file:

```
CONTRACT_ADDRESS=0x_YOUR_DEPLOYED_CONTRACT_ADDRESS_
```

The backend will interact with this contract to:
- Verify issuer registration status
- Check credential revocation status
- Listen for contract events

### Testing in Remix

Use Remix's testing framework or deploy to a local testnet for comprehensive testing:

```javascript
// Example test scenarios
1. Deploy contract
2. Register issuer with valid metadata URI
3. Try to revoke credential as non-issuer (should fail)
4. Register as issuer and revoke credential (should succeed)
5. Check revocation status
6. Test batch revocation
7. Test ownership transfer
```

### Mainnet Deployment Considerations

Before mainnet deployment:

1. **Security Audit**: Get contract audited by professionals
2. **Gas Optimization**: Review for gas efficiency improvements
3. **Upgrade Strategy**: Consider proxy patterns for upgradability
4. **Emergency Controls**: Implement additional safety mechanisms
5. **Multi-sig**: Use multi-signature wallet for owner functions

### Contract Address (Update After Deployment)

```
Sepolia Testnet: 0x_YOUR_CONTRACT_ADDRESS_HERE_
Etherscan: https://sepolia.etherscan.io/address/0x_YOUR_CONTRACT_ADDRESS_HERE_
```
