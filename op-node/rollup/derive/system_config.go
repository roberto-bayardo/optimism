package derive

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/go-multierror"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/solabi"
)

var (
	SystemConfigUpdateBatcher           = common.Hash{31: 0}
	SystemConfigUpdateGasConfig         = common.Hash{31: 1}
	SystemConfigUpdateGasLimit          = common.Hash{31: 2}
	SystemConfigUpdateUnsafeBlockSigner = common.Hash{31: 3}

	addressPadding [12]byte = [12]byte{}
)

var (
	ConfigUpdateEventABI      = "ConfigUpdate(uint256,uint8,bytes)"
	ConfigUpdateEventABIHash  = crypto.Keccak256Hash([]byte(ConfigUpdateEventABI))
	ConfigUpdateEventVersion0 = common.Hash{}
)

// UpdateSystemConfigWithL1Receipts filters all L1 receipts to find config updates and applies the config updates to the given sysCfg
func UpdateSystemConfigWithL1Receipts(sysCfg *eth.SystemConfig, receipts []*types.Receipt, cfg *rollup.Config) error {
	var result error
	for i, rec := range receipts {
		if rec.Status != types.ReceiptStatusSuccessful {
			continue
		}
		for j, log := range rec.Logs {
			if log.Address == cfg.L1SystemConfigAddress && len(log.Topics) > 0 && log.Topics[0] == ConfigUpdateEventABIHash {
				if err := ProcessSystemConfigUpdateLogEvent(sysCfg, log); err != nil {
					result = multierror.Append(result, fmt.Errorf("malformatted L1 system sysCfg log in receipt %d, log %d: %w", i, j, err))
				}
			}
		}
	}
	return result
}

// ProcessSystemConfigUpdateLogEvent decodes an EVM log entry emitted by the system config contract and applies it as a system config change.
//
// parse log data for:
//
//	event ConfigUpdate(
//	    uint256 indexed version,
//	    UpdateType indexed updateType,
//	    bytes data
//	);
func ProcessSystemConfigUpdateLogEvent(destSysCfg *eth.SystemConfig, ev *types.Log) error {
	if len(ev.Topics) != 3 {
		return fmt.Errorf("expected 3 event topics (event identity, indexed version, indexed updateType), got %d", len(ev.Topics))
	}
	if ev.Topics[0] != ConfigUpdateEventABIHash {
		return fmt.Errorf("invalid SystemConfig update event: %s, expected %s", ev.Topics[0], ConfigUpdateEventABIHash)
	}

	// indexed 0
	version := ev.Topics[1]
	if version != ConfigUpdateEventVersion0 {
		return fmt.Errorf("unrecognized SystemConfig update event version: %s", version)
	}
	// indexed 1
	updateType := ev.Topics[2]

	// Create a reader of the unindexed data
	reader := bytes.NewReader(ev.Data)

	// Attempt to read unindexed data
	switch updateType {
	case SystemConfigUpdateBatcher:
		if pointer, err := solabi.ReadUint64(reader); err != nil || pointer != 32 {
			return NewCriticalError(errors.New("invalid pointer field"))
		}
		if length, err := solabi.ReadUint64(reader); err != nil || length != 32 {
			return NewCriticalError(errors.New("invalid length field"))
		}
		v, a, b, err := ReadVersionedBatcherHash(reader)
		if err != nil {
			return NewCriticalError(fmt.Errorf("invalid versioned batcher address: %w", err))
		}
		if !solabi.EmptyReader(reader) {
			return NewCriticalError(errors.New("too many bytes"))
		}
		// TODO: make sure version == 0 if we've yet to pass blob activation time
		destSysCfg.BatcherHashVersion, destSysCfg.BatcherAddr, destSysCfg.CanUseBlobs = v, a, b
		return nil
	case SystemConfigUpdateGasConfig:
		if pointer, err := solabi.ReadUint64(reader); err != nil || pointer != 32 {
			return NewCriticalError(errors.New("invalid pointer field"))
		}
		if length, err := solabi.ReadUint64(reader); err != nil || length != 64 {
			return NewCriticalError(errors.New("invalid length field"))
		}
		overhead, err := solabi.ReadEthBytes32(reader)
		if err != nil {
			return NewCriticalError(errors.New("could not read overhead"))
		}
		scalar, err := solabi.ReadEthBytes32(reader)
		if err != nil {
			return NewCriticalError(errors.New("could not read scalar"))
		}
		if !solabi.EmptyReader(reader) {
			return NewCriticalError(errors.New("too many bytes"))
		}
		destSysCfg.Overhead = overhead
		destSysCfg.Scalar = scalar
		return nil
	case SystemConfigUpdateGasLimit:
		if pointer, err := solabi.ReadUint64(reader); err != nil || pointer != 32 {
			return NewCriticalError(errors.New("invalid pointer field"))
		}
		if length, err := solabi.ReadUint64(reader); err != nil || length != 32 {
			return NewCriticalError(errors.New("invalid length field"))
		}
		gasLimit, err := solabi.ReadUint64(reader)
		if err != nil {
			return NewCriticalError(errors.New("could not read gas limit"))
		}
		if !solabi.EmptyReader(reader) {
			return NewCriticalError(errors.New("too many bytes"))
		}
		destSysCfg.GasLimit = gasLimit
		return nil
	case SystemConfigUpdateUnsafeBlockSigner:
		// Ignored in derivation. This configurable applies to runtime configuration outside of the derivation.
		return nil
	default:
		return fmt.Errorf("unrecognized L1 sysCfg update type: %s", updateType)
	}
}

func ReadVersionedBatcherHash(r io.Reader) (v byte, a common.Address, useBlobs bool, err error) {
	a, padding, err := solabi.ReadAddressWithPadding(r)
	if err != nil {
		return v, a, useBlobs, fmt.Errorf("could not read address with padding: %w", err)
	}
	if bytes.Equal(padding[:], addressPadding[:]) {
		return v, a, false, nil
	}
	if padding[0] != 0x1 {
		return v, a, useBlobs, fmt.Errorf("unknown batcher address version: %b", padding[0])
	}
	v = padding[0]
	// For v1 batcher addresses, bit 0 of padding[0] indicates whether batch transactions can
	// be blob transactions.
	switch padding[1] {
	case 1:
		useBlobs = true
	case 0:
		useBlobs = false
	default:
		return v, a, useBlobs, fmt.Errorf("unknown value in byte 1 of v1 address: %b", padding[1])
	}
	if !bytes.Equal(padding[2:], addressPadding[2:]) {
		return v, a, useBlobs, errors.New("v1 address padding not empty")
	}
	return v, a, useBlobs, nil
}

func WriteVersionedBatcherHash(w io.Writer, v byte, a common.Address, useBlobs bool) error {
	var n [12]byte
	n[0] = v
	if useBlobs {
		n[1] = 0x1
	}
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	if _, err := w.Write(a[:]); err != nil {
		return err
	}
	return nil
}
