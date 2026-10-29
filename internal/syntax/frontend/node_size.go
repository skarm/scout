//goland:noinspection GoMixedReceiverTypes // JSON values marshal by value and unmarshal by pointer.
package frontend

import (
	"encoding/json"
	"strconv"
)

func quotedSize(s string) int {
	encoded, _ := json.Marshal(s)
	return len(encoded)
}

func nodeHeaderSize(kind string, start, end int) int {
	return len(`{"type":,"start":,"end":}`) + quotedSize(kind) + len(strconv.Itoa(start)) + len(strconv.Itoa(end))
}

// encodedSize preserves the existing output budget without serializing nested
// nodes. A normalized child's encoded size is fixed before it is attached.
func (v Value) encodedSize() int {
	switch v.kind {
	case valueNodes:
		size := arraySize(len(v.children))
		for _, child := range v.children {
			size += nodeEncodedSize(child)
		}

		return size
	case valueStrings:
		size := arraySize(len(v.strings))
		for _, text := range v.strings {
			size += quotedSize(text)
		}

		return size
	case valueNode:
		return nodeEncodedSize(v.child)
	default:
		return v.scalarEncodedSize()
	}
}

func arraySize(length int) int { return 2 + max(0, length-1) }
func nodeEncodedSize(n *Node) int {
	if n == nil {
		return 4
	}

	return n.encoded
}

func (v Value) scalarEncodedSize() int {
	switch v.kind {
	case ValueNull:
		return 4
	case ValueString:
		return quotedSize(v.text)
	case ValueBool:
		if v.boolean {
			return 4
		}

		return 5
	case ValueInteger:
		return len(strconv.FormatInt(v.integer, 10))
	case ValueNumber:
		return len(v.text)
	case valueBytes:
		return len(`{"bytes_hex":""}`) + 2*len(v.bytes)
	default:
		// Composite values are sized separately by encodedSize.
		return 0
	}
}
