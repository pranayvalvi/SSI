// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IssuerRegistry
 * @dev Smart contract for managing verifiable credential issuers and credential revocation
 * @notice This contract allows registration of credential issuers and tracking of revoked credentials
 */
contract IssuerRegistry {
    address public owner;
    
    struct Issuer {
        address addr;
        string metadataUri; // IPFS CID or URL containing issuer metadata
        uint256 registeredAt;
        bool exists;
        bool isActive;
    }

    // Mapping from credential hash to revocation status
    mapping(bytes32 => bool) public revoked;
    
    // Mapping from issuer address to issuer details
    mapping(address => Issuer) public issuers;
    
    // Array to track all registered issuers
    address[] public issuerList;
    
    // Events
    event IssuerRegistered(
        address indexed issuer, 
        string metadataUri, 
        uint256 timestamp
    );
    
    event IssuerUpdated(
        address indexed issuer, 
        string metadataUri, 
        uint256 timestamp
    );
    
    event IssuerStatusChanged(
        address indexed issuer, 
        bool isActive, 
        uint256 timestamp
    );
    
    event CredentialRevoked(
        bytes32 indexed credentialHash, 
        address indexed revokedBy, 
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        address indexed previousOwner, 
        address indexed newOwner
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "IssuerRegistry: caller is not the owner");
        _;
    }
    
    modifier onlyRegisteredIssuer() {
        require(issuers[msg.sender].exists, "IssuerRegistry: caller is not a registered issuer");
        require(issuers[msg.sender].isActive, "IssuerRegistry: issuer is not active");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @dev Register a new issuer with metadata stored on IPFS
     * @param issuerAddr The Ethereum address of the issuer
     * @param metadataUri IPFS URI containing issuer metadata (name, description, etc.)
     */
    function registerIssuer(address issuerAddr, string calldata metadataUri) external {
        require(issuerAddr != address(0), "IssuerRegistry: invalid issuer address");
        require(bytes(metadataUri).length > 0, "IssuerRegistry: metadata URI cannot be empty");
        
        Issuer storage issuer = issuers[issuerAddr];
        
        if (!issuer.exists) {
            // New issuer registration
            issuerList.push(issuerAddr);
            issuer.exists = true;
            issuer.addr = issuerAddr;
            issuer.registeredAt = block.timestamp;
            issuer.isActive = true;
        }
        
        issuer.metadataUri = metadataUri;
        emit IssuerRegistered(issuerAddr, metadataUri, block.timestamp);
    }

    /**
     * @dev Update issuer metadata (only the issuer themselves or owner can update)
     * @param issuerAddr The issuer address to update
     * @param metadataUri New IPFS URI for metadata
     */
    function updateIssuer(address issuerAddr, string calldata metadataUri) external {
        require(issuerAddr != address(0), "IssuerRegistry: invalid issuer address");
        require(bytes(metadataUri).length > 0, "IssuerRegistry: metadata URI cannot be empty");
        require(
            msg.sender == issuerAddr || msg.sender == owner, 
            "IssuerRegistry: unauthorized to update issuer"
        );
        
        Issuer storage issuer = issuers[issuerAddr];
        require(issuer.exists, "IssuerRegistry: issuer not registered");
        
        issuer.metadataUri = metadataUri;
        emit IssuerUpdated(issuerAddr, metadataUri, block.timestamp);
    }

    /**
     * @dev Activate or deactivate an issuer (only owner)
     * @param issuerAddr The issuer address
     * @param isActive New active status
     */
    function setIssuerStatus(address issuerAddr, bool isActive) external onlyOwner {
        require(issuerAddr != address(0), "IssuerRegistry: invalid issuer address");
        
        Issuer storage issuer = issuers[issuerAddr];
        require(issuer.exists, "IssuerRegistry: issuer not registered");
        
        issuer.isActive = isActive;
        emit IssuerStatusChanged(issuerAddr, isActive, block.timestamp);
    }

    /**
     * @dev Revoke a credential by its hash
     * @param credentialHash The keccak256 hash of the credential to revoke
     */
    function revokeCredential(bytes32 credentialHash) external onlyRegisteredIssuer {
        require(credentialHash != bytes32(0), "IssuerRegistry: invalid credential hash");
        require(!revoked[credentialHash], "IssuerRegistry: credential already revoked");
        
        revoked[credentialHash] = true;
        emit CredentialRevoked(credentialHash, msg.sender, block.timestamp);
    }

    /**
     * @dev Batch revoke multiple credentials
     * @param credentialHashes Array of credential hashes to revoke
     */
    function batchRevokeCredentials(bytes32[] calldata credentialHashes) external onlyRegisteredIssuer {
        require(credentialHashes.length > 0, "IssuerRegistry: empty credentials array");
        require(credentialHashes.length <= 50, "IssuerRegistry: too many credentials in batch");
        
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            bytes32 credHash = credentialHashes[i];
            require(credHash != bytes32(0), "IssuerRegistry: invalid credential hash");
            
            if (!revoked[credHash]) {
                revoked[credHash] = true;
                emit CredentialRevoked(credHash, msg.sender, block.timestamp);
            }
        }
    }

    /**
     * @dev Check if an address is a registered and active issuer
     * @param issuerAddr The address to check
     * @return bool True if the address is a registered and active issuer
     */
    function isIssuerRegistered(address issuerAddr) external view returns (bool) {
        return issuers[issuerAddr].exists && issuers[issuerAddr].isActive;
    }

    /**
     * @dev Check if a credential is revoked
     * @param credentialHash The credential hash to check
     * @return bool True if the credential is revoked
     */
    function isCredentialRevoked(bytes32 credentialHash) external view returns (bool) {
        return revoked[credentialHash];
    }

    /**
     * @dev Get issuer metadata URI
     * @param issuerAddr The issuer address
     * @return string The IPFS URI containing issuer metadata
     */
    function getIssuerMetadata(address issuerAddr) external view returns (string memory) {
        require(issuers[issuerAddr].exists, "IssuerRegistry: issuer not registered");
        return issuers[issuerAddr].metadataUri;
    }

    /**
     * @dev Get complete issuer information
     * @param issuerAddr The issuer address
     * @return Issuer struct containing all issuer details
     */
    function getIssuer(address issuerAddr) external view returns (Issuer memory) {
        require(issuers[issuerAddr].exists, "IssuerRegistry: issuer not registered");
        return issuers[issuerAddr];
    }

    /**
     * @dev Get the total number of registered issuers
     * @return uint256 The count of registered issuers
     */
    function getIssuerCount() external view returns (uint256) {
        return issuerList.length;
    }

    /**
     * @dev Get issuer address by index
     * @param index The index in the issuer list
     * @return address The issuer address at the given index
     */
    function getIssuerByIndex(uint256 index) external view returns (address) {
        require(index < issuerList.length, "IssuerRegistry: index out of bounds");
        return issuerList[index];
    }

    /**
     * @dev Transfer ownership of the contract
     * @param newOwner The address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "IssuerRegistry: new owner is the zero address");
        require(newOwner != owner, "IssuerRegistry: new owner is the same as current owner");
        
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev Emergency function to pause/unpause issuer operations (future enhancement)
     * This can be extended to implement pausable functionality if needed
     */
    function emergencyStop() external onlyOwner {
        // Implementation for emergency stop functionality
        // This is a placeholder for future emergency controls
    }
}
