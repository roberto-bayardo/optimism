package client

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

type EthClient4844 struct {
	// until geth PR 27841 lands we have a separate txpool.Transaction type to send over the transaction RPC
	// and even then, the ethclient bindings have to be updated
	// to take the blobs sidecar and pass along the blobs contents via outer RPC fields.
	*ethclient.Client
}

func (cl *EthClient4844) SendTransaction4844(ctx context.Context, tx *txpool.Transaction) error {
	if len(tx.BlobTxBlobs) == 0 {
		return cl.SendTransaction(ctx, tx.Tx)
	}
	rpcClient := cl.Client.Client()

	data := &types.BlobTxWithBlobs{
		Transaction: *tx.Tx,
		Blobs:       tx.BlobTxBlobs,
		Commitments: tx.BlobTxCommits,
		Proofs:      tx.BlobTxProofs,
	}
	payload, err := rlp.EncodeToBytes(data)
	if err != nil {
		return err
	}
	return rpcClient.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Bytes(payload))
}
