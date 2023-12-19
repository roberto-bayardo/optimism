// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { ISemver } from "src/universal/ISemver.sol";

/// @custom:proxied
/// @custom:predeploy 0x4200000000000000000000000000000000000015
/// @title L1Block
/// @notice The L1Block predeploy gives users access to information about the last known L1 block.
///         Values within this contract are updated once per epoch (every L1 block) and can only be
///         set by the "depositor" account, a special system address. Depositor account transactions
///         are created by the protocol whenever we move to a new epoch.
contract L1Block is ISemver {
    /// @notice Address of the special depositor account.
    address public constant DEPOSITOR_ACCOUNT = 0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001;

    /// @notice The latest L1 block number known by the L2 system.
    uint64 public number;

    /// @notice The latest L1 timestamp known by the L2 system.
    uint64 public timestamp;

    /// @notice The latest L1 basefee.
    uint256 public basefee;

    /// @notice The latest L1 blockhash.
    bytes32 public hash;

    /// @notice The number of L2 blocks in the same epoch.
    uint64 public sequenceNumber;

    /// @notice The versioned hash to authenticate the batcher by.
    bytes32 public batcherHash;

    /// @notice The overhead value applied to the L1 portion of the transaction fee.
    /// @custom:legacy
    uint256 public l1FeeOverhead;

    /// @notice The scalar value applied to the L1 portion of the transaction fee.
    /// @custom:legacy
    uint256 public l1FeeScalar;

    /// @notice The latest L1 blob basefee.
    uint256 public blobBaseFee;

    /// @notice The scalar value applied to the L1 base fee portion of the blob-capable L1 cost func
	uint32 public baseFeeScalar;

    /// @notice The scalar value applied to the L1 blob base fee portion of the blob-capable L1 cost func
	uint32 public blobBaseFeeScalar;

    /// @custom:semver 1.2.0
    string public constant version = "1.2.0";

    /// @custom:legacy
    /// @notice Updates the L1 block values.
    /// @param _number         L1 blocknumber.
    /// @param _timestamp      L1 timestamp.
    /// @param _basefee        L1 basefee.
    /// @param _hash           L1 blockhash.
    /// @param _sequenceNumber Number of L2 blocks since epoch start.
    /// @param _batcherHash    Versioned hash to authenticate batcher by.
    /// @param _l1FeeOverhead  L1 fee overhead.
    /// @param _l1FeeScalar    L1 fee scalar.
    function setL1BlockValues(
        uint64 _number,
        uint64 _timestamp,
        uint256 _basefee,
        bytes32 _hash,
        uint64 _sequenceNumber,
        bytes32 _batcherHash,
        uint256 _l1FeeOverhead,
        uint256 _l1FeeScalar
    )
        external
    {
        require(msg.sender == DEPOSITOR_ACCOUNT, "L1Block: only the depositor account can set L1 block values");

        number = _number;
        timestamp = _timestamp;
        basefee = _basefee;
        hash = _hash;
        sequenceNumber = _sequenceNumber;
        batcherHash = _batcherHash;
        l1FeeOverhead = _l1FeeOverhead;
        l1FeeScalar = _l1FeeScalar;

        (uint256 _blobBaseFee) = abi.decode(msg.data[260:], (uint256));
        blobBaseFeeScalar = 1;
        baseFeeScalar = 1;
        blobBaseFee = _blobBaseFee;

    }

    /// @notice Updates the L1 block values for a post-blob activated chain.
    /// Params are passed in as part of msg.data in order to compress the calldata.
    /// Params should be passed in in the following order:
    ///   1. _number             L1 blocknumber.
    ///   2. _timestamp          L1 timestamp.
    ///   3. _basefee            L1 basefee.
    ///   4. _blobBaseFee        L1 blobBaseFee.
    ///   5. _hash               L1 blockhash.
    ///   6. _sequenceNumber     Number of L2 blocks since epoch start.
    ///   7. _batcherHash        Versioned hash to authenticate batcher by.
    ///   8. _baseFeeScalar      L1 base fee scalar
    ///   9. _blobBaseFeeScalar  L1 blob base fee scalar
    function setL1BlockValuesV2() external {
        require(msg.sender == DEPOSITOR_ACCOUNT, "L1Block: only the depositor account can set L1 block values");

        bytes memory _data = msg.data[4:];
        // if (_msgData.length != XXX) { // TODO: configure
        //     revert("L1Block: invalid msg.data length");
        // }

        uint64 _number;
        uint64 _timestamp;
        uint256 _basefee;
        uint256 _blobBaseFee;
        bytes32 _hash;
        uint64 _sequenceNumber;
        bytes32 _batcherHash;
        uint32 _baseFeeScalar;
        uint32 _blobBaseFeeScalar;

        assembly {
            _number := mload(add(_data, 0x8))
            _timestamp := shr(48, mload(add(_data, 0x16)))
            _basefee := shr(192, mload(add(_data, 0x48)))
        }

        // TODO calculations for rest
        // _blobBaseFee := 
        // _hash := 
        // _sequenceNumber := 
        // _batcherHash := 
        // _baseFeeScalar := 
        // _blobBaseFeeScalar := 

        number = _number;
        timestamp = _timestamp;
        basefee = _basefee;
        blobBaseFee = _blobBaseFee;
        hash = _hash;
        sequenceNumber = _sequenceNumber;
        batcherHash = _batcherHash;
        baseFeeScalar = _baseFeeScalar;
        blobBaseFeeScalar = _blobBaseFeeScalar;
    }
}
