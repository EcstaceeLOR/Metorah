// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Registry of source-authorized destination bindings scoped to one migration and destination.
/// @dev The authorized attesters must validate frozen source registration or an approved source signature
/// off-chain. This registry does not itself verify Substrate finality or prove the source account exists.
contract SourceAuthorizedBindings {
    bytes32 private constant TYPEHASH = keccak256(
        "SourceBinding(bytes32 migrationId,bytes32 sourceAccountId,address beneficiary,uint256 chainId,address registry,uint64 validUntil)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("Metorah Source Authorized Bindings");
    bytes32 private constant VERSION_HASH = keccak256("1");

    bytes32 public immutable migrationId;
    uint8 public immutable quorum;
    mapping(address => bool) public authorizedAttester;
    mapping(bytes32 => address) public beneficiaryOf;
    mapping(bytes32 => bool) public bound;

    event BindingRegistered(bytes32 indexed sourceAccountId, address indexed beneficiary, bytes32 indexed bindingDigest);

    error InvalidConfiguration();
    error InvalidAttestations();
    error AlreadyBound();
    error ExpiredBinding();
    error InvalidBinding();

    constructor(bytes32 migrationId_, uint8 quorum_, address[] memory attesters) {
        if (migrationId_ == bytes32(0) || quorum_ == 0 || attesters.length < quorum_) revert InvalidConfiguration();
        migrationId = migrationId_;
        quorum = quorum_;
        for (uint256 i; i < attesters.length; ++i) {
            address a = attesters[i];
            if (a == address(0) || authorizedAttester[a]) revert InvalidConfiguration();
            authorizedAttester[a] = true;
        }
    }

    function bindingDigest(bytes32 sourceAccountId, address beneficiary, uint64 validUntil)
        public view returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, migrationId, sourceAccountId, beneficiary, block.chainid, address(this), validUntil
        ));
        bytes32 domain = keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)
        ));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function registerBinding(
        bytes32 sourceAccountId,
        address beneficiary,
        uint64 validUntil,
        bytes[] calldata signatures
    ) external {
        if (sourceAccountId == bytes32(0) || beneficiary == address(0)) revert InvalidBinding();
        if (bound[sourceAccountId]) revert AlreadyBound();
        if (validUntil < block.timestamp) revert ExpiredBinding();
        bytes32 digest = bindingDigest(sourceAccountId, beneficiary, validUntil);
        address previous;
        uint256 valid;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (!authorizedAttester[signer] || signer <= previous) revert InvalidAttestations();
            previous = signer;
            ++valid;
        }
        if (valid < quorum) revert InvalidAttestations();
        bound[sourceAccountId] = true;
        beneficiaryOf[sourceAccountId] = beneficiary;
        emit BindingRegistered(sourceAccountId, beneficiary, digest);
    }

    function verifyBinding(bytes32 sourceAccountId, address beneficiary) external view returns (bool) {
        return bound[sourceAccountId] && beneficiaryOf[sourceAccountId] == beneficiary;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 ||
            (v != 27 && v != 28)) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}
