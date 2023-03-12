package encrypt

import (
	"crypto/sha256"
	"errors"
)

func SplitBytes(data []byte) ([][]byte, error) {
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

func AgroCrypt(data [][]byte) []byte {
	// this function will encrypt the given 2D array by running through
	// a series of movements loosely based on AES.

	working := data
	// spin the rows
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			working[i][j], working[(i+1)%4][j] = working[(i+1)%4][j], working[i][j]
		}
	}

	// spin the cols
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			working[i][j], working[i][(j+1)%4] = working[i][(j+1)%4], working[i][j]
		}
	}

	// flatten everything
	retval := make([]byte, 16)
	for i := range working {
		retval = append(retval, working[i]...)
	}
	return retval
}

// func jumble(obj []byte) []byte {
// 	// this function jumbles the given object somehow.
// 	// right now i will just reverse
// 	retval := make([]byte, len(obj))
// 	for i, v := range obj {
// 		retval[len(obj)-(i+1)] = v
// 	}
// 	return retval
// }

// func roundFunction(P, K []byte) []byte {
// 	// this will perform some sort of math on a byte string
// 	// based on the key provided

// 	var loopVal []byte

// 	if
// 	if len(P) >= len(K) {
// 		// plaintext is longer than key, loop on plaintext
// 		retval := make([]byte, len(P))
// 		for i := range P {
// 			retval[i] = (P[i] ^ K[i]) % 255
// 		}
// 	} else {
// 		retval := make([]byte, len(K))
// 		for i := range K {
// 			retval[i] = (P[i] ^ K[i]) % 255
// 		}
// 	}
// 	thisHash := sha256.Sum256(retval)
// }

func FeistalEncrypt(obj []byte, key string, rounds int) []byte {
	// Feistal network

	left := obj[:len(obj)/2]
	right := obj[len(obj)/2:]

	for i := 0; i < rounds; i++ {

		// rightFunction := right
		// rightFunction = append(rightFunction, []byte(key)...)

		hash := sha256.Sum256([]byte(key))

		for j := range left {
			left[j] ^= hash[j]
		}

		// now swap
		left, right = right, left
	}

	retval := left
	retval = append(retval, right...)
	return retval
}

// func FeistalDecrypt(obj []byte, key string, rounds int) []byte {
// 	// this will de
// }
