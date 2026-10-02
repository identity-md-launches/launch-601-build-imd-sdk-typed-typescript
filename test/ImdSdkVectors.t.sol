// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Independent on-chain-style check of the SDK's signing vectors.
/// The JS suite asserts that LocalPrivateKeySigner produces exactly these signatures for the
/// Permit2 PermitWitnessTransferFrom and IdentityMD QuoteApproval typed data. This test rebuilds the
/// EIP-712 digests in Solidity and recovers the signer with ecrecover, so a drift in either the SDK's
/// hashing or its secp256k1 code is caught by an implementation that shares none of it.
/// It also pins the secp256k1 scalar collision that finding 11 of the audit of 91407cb refuses:
/// the overflowed key N + 5 used to publish the address of scalar 5.
contract ImdSdkVectorsTest {
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    address internal constant SIGNER = 0x0F740EEC79B13A840AC194A801aa5D55741f873b;
    address internal constant ASSET = 0xD34a99Bc0f67aE1bbd63C660e6d0b0dd03E263B7;
    address internal constant PAY_TO = 0x4e0fA57Bde726079356537E2F34d671E9F41ADbc;
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address internal constant PROXY = 0x402085c248EeA27D92E8b30b2C58ed07f9E20001;

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 internal constant WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter)");
    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)"
    );
    bytes32 internal constant APPROVAL_TYPEHASH = keccak256(
        "QuoteApproval(string resource,bytes32 requesterScopeHash,string quoteId,bytes32 quoteHash,bytes32 paymentHash,string action,address asset,uint256 amount,address payTo,uint256 expiresAt)"
    );

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "ecrecover failed");
        return recovered;
    }

    /// @dev Permit2 vector from test/paid-flow.test.mjs: domain Permit2 / chainId 1 / Permit2 contract, no version.
    function testPermit2VectorRecoversSdkSigner() public pure {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("Permit2"),
                uint256(1),
                PERMIT2
            )
        );
        bytes32 permitted = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, ASSET, uint256(500000000000000000)));
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, PAY_TO, uint256(0)));
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, permitted, PROXY, uint256(42), uint256(1800000000), witness));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        bytes memory signature =
            hex"a8907e60b697953cff765db4b18e12dbb1e740d9292422423160d8d10ea6541643e1dd028ebec7e76ef4da69c2cf9781bff323cac998925413b764dd1d4e15b91c";
        require(recover(digest, signature) == SIGNER, "Permit2 vector does not recover the SDK signer");
    }

    /// @dev QuoteApproval vector from test/paid-flow.test.mjs: domain IdentityMD Paid Action / 1 / chainId 1.
    function testQuoteApprovalVectorRecoversSdkSigner() public pure {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
                keccak256("IdentityMD Paid Action"),
                keccak256("1"),
                uint256(1)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                APPROVAL_TYPEHASH,
                keccak256("https://api.example/requests/order-1"),
                bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
                keccak256("quote-1"),
                bytes32(0x2222222222222222222222222222222222222222222222222222222222222222),
                bytes32(0x3333333333333333333333333333333333333333333333333333333333333333),
                keccak256("job.open"),
                ASSET,
                uint256(500000000000000000),
                PAY_TO,
                uint256(1800000100)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        bytes memory signature =
            hex"9bd9e8e23679fdae27d63aedba9fbe456ed7908028702fc3d2866e941e4414bb6be709535a492e37843c6dd35a510731c9146352918f91a353c26b593a433b6c1c";
        require(recover(digest, signature) == SIGNER, "QuoteApproval vector does not recover the SDK signer");
    }

    /// @dev Address of k*G via ecrecover(0, 27, Gx, k*Gx mod N). Scalar N + 5 reduces to 5, which is the
    /// collision finding 11 describes; the SDK now rejects any key outside 0 < d < N, so this address can
    /// only ever be published for the key that actually signs for it.
    function testOverflowedScalarCollidesWithScalarFive() public pure {
        address five = ecrecover(bytes32(0), 27, bytes32(GX), bytes32(mulmod(5, GX, N)));
        require(five == 0xe1AB8145F7E55DC933d51a18c793F901A3A0b276, "scalar 5 address");
        uint256 overflowed;
        unchecked {
            overflowed = N + 5;
        }
        require(overflowed % N == 5, "N + 5 reduces to 5");
        address reduced = ecrecover(bytes32(0), 27, bytes32(GX), bytes32(mulmod(overflowed % N, GX, N)));
        require(reduced == five, "the overflowed key maps to the same address");
    }
}
