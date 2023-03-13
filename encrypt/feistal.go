package encrypt

import (
	"crypto/sha256"
	"errors"
)

func splitBytes(data []byte) ([][]byte, error) {
	// this will take a 16-byte object blob and
	// split it into 4 rows, 4 cols
	retval := make([][]byte, 4)
	if len(data) != 16 {
		return retval, errors.New("invalid byte length, need 16")
	}

	for i := 0; i < 4; i++ {
		retval[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			retval[i][j] = data[i*4+j]
		}
	}
	return retval, nil
}

func agroCrypt(data [][]byte) []byte {
	// this function will encrypt the given 2D array by running through
	// a series of movements loosely based on AES.

	working := data

	// spin the cols and rows
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			working[i][j] = ((working[i][j] + 8) * 8) % 255
			working[i][j], working[(i+2)%4][j] = working[(i+2)%4][j], working[i][j]
			working[i][j], working[i][(j+1)%4] = working[i][(j+1)%4], working[i][j]

			// XOR the bytes with its neighbor
			working[i][j] ^= working[(i+1)%4][(j+2)%4]

			// shift left
			working[i][j] <<= 1

		}
	}

	// flatten everything
	retval := make([]byte, 0)
	for i := range working {
		retval = append(retval, working[i]...)
	}
	return retval
}

func FeistalEncrypt(P, K []byte, rounds int) []byte {
	// Feistal network

	left := P[:len(P)/2]
	right := P[len(P)/2:]

	hashVal := sha256.Sum256(K)
	b, _ := splitBytes(hashVal[:16])
	key := agroCrypt(b)

	for i := 0; i < rounds; i++ {

		// rightFunction := right
		// rightFunction = append(rightFunction, []byte(key)...)
		// fmt.Printf("Key used: %#v\n", key)

		for j := range left {
			left[j] ^= key[j%16]
		}

		// now swap
		left, right = right, left

		// now bring on the next key
		hashVal = sha256.Sum256(key)
		b, _ = splitBytes(hashVal[:16])
		key = agroCrypt(b)
	}

	retval := left
	retval = append(retval, right...)
	return retval
}

// func FeistalDecrypt(obj []byte, key string, rounds int) []byte {
// 	// this will de
// }
