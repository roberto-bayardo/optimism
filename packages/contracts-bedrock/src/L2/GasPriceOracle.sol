// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { ISemver } from "src/universal/ISemver.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { L1Block } from "src/L2/L1Block.sol";

/// @custom:proxied
/// @custom:predeploy 0x420000000000000000000000000000000000000F
/// @title GasPriceOracle
/// @notice This contract maintains the variables responsible for computing the L1 portion of the
///         total fee charged on L2. Before Bedrock, this contract held variables in state that were
///         read during the state transition function to compute the L1 portion of the transaction
///         fee. After Bedrock, this contract now simply proxies the L1Block contract, which has
///         the values used to compute the L1 portion of the fee in its state.
///
///         The contract exposes an API that is useful for knowing how large the L1 portion of the
///         transaction fee will be. The following events were deprecated with Bedrock:
///         - event OverheadUpdated(uint256 overhead);
///         - event ScalarUpdated(uint256 scalar);
///         - event DecimalsUpdated(uint256 decimals);
contract GasPriceOracle is ISemver {
    /// @notice Number of decimals used in the scalar.
    uint256 public constant DECIMALS = 6;

    /// @notice Semantic version.
    /// @custom:semver 1.2.0
    string public constant version = "1.2.0";

    /// @notice Flag that indicates whether the network is in eclipse mode.
    bool public isEclipse;

    /// @notice Computes the L1 portion of the fee based on the size of the rlp encoded input
    ///         transaction, the current L1 base fee, and the various dynamic parameters.
    /// @param _data Unsigned fully RLP-encoded transaction to get the L1 fee for.
    /// @return L1 fee that should be paid for the tx
    function getL1Fee(bytes memory _data) external view returns (uint256) {
        uint256 unscaled;
        if (isEclipse) {
            uint256 l1GasUsed = _getL1GasUsed(_data);
            uint256 scaledBaseFee = baseFeeScalar() * l1BaseFee();
            uint256 scaledBlobBaseFee = blobBaseFeeScalar() * blobBaseFee();
            unscaled = l1GasUsed * (scaledBaseFee + scaledBlobBaseFee);
        } else {
            uint256 l1GasUsed = _getL1GasUsedPreEclipse(_data);
            uint256 l1Fee = l1GasUsed * l1BaseFee();
            unscaled = l1Fee * L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).l1FeeScalar();
        }
        uint256 divisor = 10 ** DECIMALS;
        uint256 scaled = unscaled / divisor;
        return scaled;
    }

    function setEclipse() external {
        require(
            msg.sender == L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).DEPOSITOR_ACCOUNT(),
            "GasPriceOracle: only the depositor account can set isEclipse flag"
        );
        isEclipse = true;
    }

    /// @notice Retrieves the current gas price (base fee).
    /// @return Current L2 gas price (base fee).
    function gasPrice() public view returns (uint256) {
        return block.basefee;
    }

    /// @notice Retrieves the current base fee.
    /// @return Current L2 base fee.
    function baseFee() public view returns (uint256) {
        return block.basefee;
    }

    /// @custom:legacy
    /// @notice Retrieves the current fee overhead.
    /// @return Current fee overhead.
    function overhead() public view returns (uint256) {
        if (isEclipse) {
            revert("GasPriceOracle: overhead() is deprecated");
        }
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).l1FeeOverhead();
    }

    /// @custom:legacy
    /// @notice Retrieves the current fee scalar.
    /// @return Current fee scalar.
    function scalar() public view returns (uint256) {
        if (isEclipse) {
            revert("GasPriceOracle: scalar() is deprecated");
        }
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).l1FeeScalar();
    }

    /// @notice Retrieves the latest known L1 base fee.
    /// @return Latest known L1 base fee.
    function l1BaseFee() public view returns (uint256) {
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).basefee();
    }

    /// @notice Retrieves the current blob base fee.
    /// @return Current blob base fee.
    function blobBaseFee() public view returns (uint256) {
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).blobBaseFee();
    }

    /// @notice Retrieves the current base fee scalar.
    /// @return Current base fee scalar.
    function baseFeeScalar() public view returns (uint32) {
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).baseFeeScalar();
    }

    /// @notice Retrieves the current blob base fee scalar.
    /// @return Current blob base fee scalar.
    function blobBaseFeeScalar() public view returns (uint32) {
        return L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).blobBaseFeeScalar();
    }

    /// @custom:legacy
    /// @notice Retrieves the number of decimals used in the scalar.
    /// @return Number of decimals used in the scalar.
    function decimals() public pure returns (uint256) {
        return DECIMALS;
    }

    /// @notice Computes the amount of L1 gas used for a transaction. Adds 68 bytes
    ///         of padding to account for the fact that the input does not have a signature.
    /// @param _data Unsigned fully RLP-encoded transaction to get the L1 gas for.
    /// @return Amount of L1 gas used to publish the transaction.
    function getL1GasUsed(bytes memory _data) public view returns (uint256) {
        if (isEclipse) {
            return _getL1GasUsed(_data);
        }
        return _getL1GasUsedPreEclipse(_data);
    }

    /// @notice Pre-eclipse L1 gas estimation calculation.
    /// @param _data Unsigned fully RLP-encoded transaction to get the L1 gas for.
    /// @return Amount of L1 gas used to publish the transaction.
    function _getL1GasUsedPreEclipse(bytes memory _data) internal view returns (uint256) {
        uint256 total = 0;
        uint256 length = _data.length;
        for (uint256 i = 0; i < length; i++) {
            if (_data[i] == 0) {
                total += 4;
            } else {
                total += 16;
            }
        }
        uint256 unsigned = total + L1Block(Predeploys.L1_BLOCK_ATTRIBUTES).l1FeeOverhead();
        return unsigned + (68 * 16);
    }

    /// @notice Post-eclipse L1 gas estimation calculation.
    /// @param _data Unsigned fully RLP-encoded transaction to get the L1 gas for.
    /// @return Amount of L1 gas used to publish the transaction.
    function _getL1GasUsed(bytes memory _data) internal pure returns (uint256) {
        uint256 total = 0;
        uint256 length = _data.length;
        for (uint256 i = 0; i < length; i++) {
            if (_data[i] == 0) {
                total += 4;
            } else {
                total += 16;
            }
        }
        return (total + (68 * 16 * 16)) / 16;
    }
}
