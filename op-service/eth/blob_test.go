package eth

import (
	"testing"
)

func TestBlobEncodeDecode(t *testing.T) {
	cases := []string{
		"this is a test of blob encoding/decoding",
		"short",
		"\x00",
		"\x00\x01\x00",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"",
	}

	var b Blob
	for _, c := range cases {
		data := Data(c)
		if err := b.FromData(data); err != nil {
			t.Fatalf("failed to encode bytes: %v", err)
		}
		decoded, err := b.ToData()
		if err != nil {
			t.Fatalf("failed to decode blob: %v", err)
		}
		if string(decoded) != c {
			t.Errorf("decoded != input. got: %v, want: %v", decoded, Data(c))
		}
	}
}

func TestSmallBlobEncoding(t *testing.T) {
	// less than 4 field elements of data
	data := Data(make([]byte, 27+31*3-6))
	data[27+31*3-7] = 0xFF
	var b Blob
	if err := b.FromData(data); err != nil {
		t.Fatalf("failed to encode bytes: %v", err)
	}
	decoded, err := b.ToData()
	if err != nil {
		t.Fatalf("failed to decode blob: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("decoded blob != small blob input")
	}

	// only 10 bytes of data
	data = Data(make([]byte, 10))
	data[9] = 0xFF
	if err := b.FromData(data); err != nil {
		t.Fatalf("failed to encode bytes: %v", err)
	}
	decoded, err = b.ToData()
	if err != nil {
		t.Fatalf("failed to decode blob: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("decoded blob != small blob input")
	}

	// no 3 bytes of extra data left to encode after the first 4 field elements
	data = Data(make([]byte, 27+31*3))
	data[27+31*3-1] = 0xFF
	if err := b.FromData(data); err != nil {
		t.Fatalf("failed to encode bytes: %v", err)
	}
	decoded, err = b.ToData()
	if err != nil {
		t.Fatalf("failed to decode blob: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("decoded blob != small blob input")
	}
}

func TestBigBlobEncoding(t *testing.T) {
	bigData := Data(make([]byte, MaxBlobDataSize-3))
	bigData[MaxBlobDataSize-4] = 0xFF
	var b Blob
	// test the maximum size of data that can be encoded
	if err := b.FromData(bigData); err != nil {
		t.Fatalf("failed to encode bytes: %v", err)
	}
	decoded, err := b.ToData()
	if err != nil {
		t.Fatalf("failed to decode blob: %v", err)
	}
	if string(decoded) != string(bigData) {
		t.Errorf("decoded blob != big blob input")
	}

	// chop off 1 byte of data at a time for 10 times
	for i := 1; i < 11; i++ {
		// test the chopped off data
		tempBigData := bigData[i:]
		if err := b.FromData(tempBigData); err != nil {
			t.Fatalf("failed to encode bytes: %v", err)
		}
		decoded, err := b.ToData()
		if err != nil {
			t.Fatalf("failed to decode blob: %v", err)
		}
		if string(decoded) != string(tempBigData) {
			t.Errorf("decoded blob != big blob input")
		}
	}
}

func TestInvalidBlobDecoding(t *testing.T) {
	data := Data("this is a test of invalid blob decoding")
	var b Blob
	if err := b.FromData(data); err != nil {
		t.Fatalf("failed to encode bytes: %v", err)
	}

	b[32] = 0x80 //field elements should never have their highest order bit set
	if _, err := b.ToData(); err == nil {
		t.Errorf("expected error, got none")
	}

	b[1] = 0x01 // wrong version of encoding
	if _, err := b.ToData(); err == nil {
		t.Errorf("expected error, got none")
	}

	b[0] = 0x00
	b[32] = 0x00
	b[4] = 0xFF // encode an invalid (much too long) length prefix
	if _, err := b.ToData(); err == nil {
		t.Errorf("expected error, got none")
	}
}

func TestTooLongDataEncoding(t *testing.T) {
	// should never be able to encode data that has size the same as that of the blob due to < 256
	// bit precision of each field element
	data := Data(make([]byte, BlobSize))
	var b Blob
	err := b.FromData(data)
	if err == nil {
		t.Errorf("expected error, got none")
	}
}
