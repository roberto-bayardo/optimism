package eth

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
)

const (
	BlobSize        = 4096 * 32
	MaxBlobDataSize = (4*31+3)*1024 - 4
	EncodingVersion = 0
	FieldSize       = 4 * 32   // size of a field composed of 4 field elements in bytes
	FieldCapacity   = 31*4 + 3 // # of bytes that can be encoded in 4 field elements
)

type Blob [BlobSize]byte

func (b *Blob) KZGBlob() *kzg4844.Blob {
	return (*kzg4844.Blob)(b)
}

func (b *Blob) UnmarshalJSON(text []byte) error {
	return hexutil.UnmarshalFixedJSON(reflect.TypeOf(b), text, b[:])
}

func (b *Blob) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("Bytes32", text, b[:])
}

func (b *Blob) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

func (b *Blob) String() string {
	return hexutil.Encode(b[:])
}

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (b *Blob) TerminalString() string {
	return fmt.Sprintf("%x..%x", b[:3], b[BlobSize-3:])
}

func (b *Blob) ComputeKZGCommitment() (kzg4844.Commitment, error) {
	return kzg4844.BlobToCommitment(*b.KZGBlob())
}

// KZGToVersionedHash computes the "blob hash" (a.k.a. versioned-hash) of a blob-commitment, as used in a blob-tx.
// We implement it here because it is unfortunately not (currently) exposed by geth.
func KZGToVersionedHash(commitment kzg4844.Commitment) (out common.Hash) {
	// EIP-4844 spec:
	//	def kzg_to_versioned_hash(commitment: KZGCommitment) -> VersionedHash:
	//		return VERSIONED_HASH_VERSION_KZG + sha256(commitment)[1:]
	h := sha256.New()
	h.Write(commitment[:])
	_ = h.Sum(out[:0])
	out[0] = params.BlobTxHashVersion
	return out
}

// VerifyBlobProof verifies that the given blob and proof corresponds to the given commitment,
// returning error if the verification fails.
func VerifyBlobProof(blob *Blob, commitment kzg4844.Commitment, proof kzg4844.Proof) error {
	return kzg4844.VerifyBlobProof(*blob.KZGBlob(), commitment, proof)
}

// FromData encodes the given input data into this blob. The encoding scheme is as follows:
// First, divide the data into 4-byte chunks. Each chunk is encoded into a field as a big-endian uint256 in BLS modulus range.
// A field is composed of 4 field elements, each of which will contain 31 bytes of data. And the 4 bytes of remaining storage
// in each field element will be used to encode the next 3 bytes of data.
// This process is repeated until all data is encoded.
// For the first field, [1:5] bytes of the first field element will be used to encode the version and the length of the data.
func (b *Blob) FromData(data Data) error {
	if len(data) > MaxBlobDataSize {
		return fmt.Errorf("data is too large for blob. len=%v", len(data))
	}
	b.Clear()

	// first field element encodes the version and the length of the data in [1:5]
	b[1] = EncodingVersion

	// encode the length as big-endian uint24 into [2:5] bytes of the first field element
	if len(data) < 1<<24 {
		// Zero out any trailing data in the buffer if any
		b[2] = byte((len(data) >> 16) & 0xFF) // Most significant byte
		b[3] = byte((len(data) >> 8) & 0xFF)
		b[4] = byte(len(data) & 0xFF) // Least significant byte
	} else {
		return fmt.Errorf("Error: length_rollup_data is too large")
	}

	// encode the first 27 + 31*3 bytes of data into remaining bytes of first four field element
	// encode the first 27 bytes of data into remaining bytes of first field element
	offset := copy(b[5:32], data)

	// for loop to encode the next 31 bytes of data into [1:] of the next three field elements
	for fieldNumber := 1; fieldNumber < 4; fieldNumber++ {
		fieldStartIndex := fieldNumber * 32
		offset += copy(b[fieldStartIndex+1:fieldStartIndex+32], data[offset:])
		if offset == len(data) {
			return nil
		}
	}

	// encode the next 3 bytes of data into the four remaining bytes of the first four field elements
	remainingData := make([]byte, 3)
	for i := 0; i < 3; i++ {
		offset += copy(remainingData[i:i+1], data[offset:])
		if offset == len(data) {
			break
		}
	}
	encodeThreeBytes(0, remainingData, b)

	if offset == len(data) {
		return nil
	}

	for fieldNumber := 1; fieldNumber < 1024; fieldNumber++ {
		for fieldElementNumber := 0; fieldElementNumber < 4; fieldElementNumber++ {
			elementStartIndex := fieldNumber*FieldSize + fieldElementNumber*32
			offset += copy(b[elementStartIndex+1:elementStartIndex+32], data[offset:])
			if offset == len(data) {
				break
			}
		}
		if offset == len(data) {
			break
		}

		// encode the next 3 bytes of data into the four remaining bytes of the first four field elements
		remainingData := make([]byte, 3)
		for j := 0; j < 3; j++ {
			offset += copy(remainingData[j:j+1], data[offset:])
			if offset == len(data) {
				break
			}
		}

		encodeThreeBytes(fieldNumber, remainingData, b)

		if offset == len(data) {
			break
		}
	}

	if offset < len(data) {
		return fmt.Errorf("failed to fit all data into blob. bytes remaining: %v", len(data)-offset)
	}

	return nil
}

func encodeThreeBytes(index int, remainingData []byte, b *Blob) {
	// copy the last 6 bits of remainingData[0] into the first byte of the first field element
	b[index*FieldSize] = remainingData[0] & 0b0011_1111
	// copy the last 6 bits of remainingData[1] into the first byte of the second field element
	b[index*FieldSize+32] = remainingData[1] & 0b0011_1111
	// copy the last 6 bits of remainingData[2] into the first byte of the third field element
	b[index*FieldSize+64] = remainingData[2] & 0b0011_1111
	// copy the first 2 bits of all remainingData bytes into the first byte of the fourth field element
	b[index*FieldSize+96] = ((remainingData[0] & 0b1100_0000) >> 2) | ((remainingData[1] & 0b1100_0000) >> 4) | ((remainingData[2] & 0b1100_0000) >> 6)
}

// ToData decodes the blob into raw byte data. See FromData above for details on the encoding
// format.
func (b *Blob) ToData() (Data, error) {
	data := make(Data, BlobSize)
	firstField := b[:FieldSize]

	// check the version
	if firstField[1] != EncodingVersion {
		return nil, fmt.Errorf("invalid blob, expected version %d, got %d", EncodingVersion, firstField[0])
	}

	// decode the 3-byte length prefix into 4-byte integer
	var dataLen int32

	// Assuming b[2], b[3], and b[4] contain the encoded length in big-endian format
	dataLen = int32(b[2]) << 16 // Shift the most significant byte 16 bits to the left
	dataLen |= int32(b[3]) << 8 // Shift the next byte 8 bits to the left and OR it with the current length
	dataLen |= int32(b[4])      // OR the least significant byte with the current length

	if dataLen > (int32)(len(data)) {
		return nil, fmt.Errorf("invalid blob, length prefix out of range: %d", dataLen)
	}

	// copy the first 27 bytes of the first field element into the output
	copy(data[:27], firstField[5:32])

	// copy the remaining 31*3 bytes of the first field into the output
	for i := 1; i < 4; i++ {
		// check that the highest order bit of the first byte of each field element is not set
		if firstField[i*32]&(1<<7) != 0 {
			return nil, fmt.Errorf("invalid blob, field element %d has highest order bit set", i)
		}
		copy(data[27+31*(i-1):], b[i*32+1:i*32+32])
	}

	// Decode the first byte of each field element in the first field
	decodedData := make([]byte, 3)

	// Decode the last 6 bits from the first byte of the first, second, and third field elements
	decodedData[0] = b[0] & 0b0011_1111
	decodedData[1] = b[32] & 0b0011_1111
	decodedData[2] = b[64] & 0b0011_1111

	// Extract the first 2 bits of all remainingData bytes from the first byte of the fourth field element
	decodedData[0] |= (b[96] & 0b0011_0000) << 2
	decodedData[1] |= (b[96] & 0b0000_1100) << 4
	decodedData[2] |= (b[96] & 0b0000_0011) << 6

	// copy the decoded data into the output
	copy(data[27+31*3:], decodedData)

	// for loop to decode 128 bytes of data at a time from the next 4 field elements
	for i := 1; i < 1024; i++ {
		for j := 0; j < 4; j++ {
			// check that the highest order bit of the first byte of each field element is not set
			if b[i*FieldSize+j*32]&(1<<7) != 0 {
				return nil, fmt.Errorf("invalid blob, field element %d has highest order bit set", i)
			}
			// -4 because of 1 byte of version and 3 bytes of length prefix
			copy(data[FieldCapacity*i+j*31-4:FieldCapacity*i+(j+1)*31-4], b[i*FieldSize+j*32+1:])
		}
		// Decode the first byte of each field element in the first field
		decodedData := make([]byte, 3)

		// Decode the last 6 bits from the first byte of the first, second, and third field elements
		decodedData[0] = b[FieldSize*i] & 0b0011_1111
		decodedData[1] = b[FieldSize*i+32] & 0b0011_1111
		decodedData[2] = b[FieldSize*i+64] & 0b0011_1111

		// Extract the first 2 bits of all remainingData bytes from the first byte of the fourth field element
		decodedData[0] |= (b[FieldSize*i+96] & 0b0011_0000) << 2
		decodedData[1] |= (b[FieldSize*i+96] & 0b0000_1100) << 4
		decodedData[2] |= (b[FieldSize*i+96] & 0b0000_0011) << 6

		// copy the decoded data into the output
		copy(data[120+FieldCapacity*i:], decodedData)
	}
	data = data[:dataLen]

	return data, nil
}

func (b *Blob) Clear() {
	for i := 0; i < BlobSize; i++ {
		b[i] = 0
	}
}
