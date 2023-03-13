package encrypt

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
)

// import "io"

// /*
// 	This will encrypt a bytestream using _better_ ways
// */

func GenerateRandomBytes(n int) ([]byte, error) {
	randBytes := make([]byte, n)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

func FileEncrypt(fileName, encExt string, key []byte) error {
	// this function will use stream encryption to encrypt
	// a file. Will throw an error if the file doesn't exist or
	// couldn't write or whatever.
	switch len(key) {
	case 16, 24, 32:
	default:
		return errors.New("need 16, 24, or 32 byte key length")
	}

	// open the file for reading
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	// now open the outfile for writing
	outFilename := fmt.Sprintf("%s.%s", fileName, encExt)
	wf, err := os.OpenFile(outFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer wf.Close()
	writer := bufio.NewWriter(wf)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return err
	}
	// var out bytes.Buffer
	stream := cipher.NewOFB(block, iv)

	// write the IV to the ciphertext buffer
	for i := 0; i < len(iv); i++ {
		writer.WriteByte(iv[i])
	}

	workingBuf := make([]byte, 1024)

	for {
		bytesRead, err := reader.Read(workingBuf)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		// now encrypt the data
		stream.XORKeyStream(workingBuf[:bytesRead], workingBuf[:bytesRead])

		_, err = writer.Write(workingBuf[:bytesRead])
		if err != nil {
			return err
		}
	}

	return nil
}

func FileDecrypt(fileName, decExt string, key []byte) error {
	switch len(key) {
	case 16, 24, 32:
	default:
		return errors.New("need 16, 24, or 32 byte key length")
	}

	// open the file for reading
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	// now open the outfile for writing
	outFilename := fmt.Sprintf("%s.%s", fileName, decExt)
	wf, err := os.OpenFile(outFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer wf.Close()
	writer := bufio.NewWriter(wf)

	// set up the aes block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// extract the initialization vector
	iv := make([]byte, aes.BlockSize)
	_, err = reader.Read(iv)
	if err != nil {
		return err
	}

	// set up the stream
	stream := cipher.NewOFB(block, iv)

	// the working buffer
	workingBuf := make([]byte, 1024)

	for {
		bytesRead, err := reader.Read(workingBuf)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		// decrypt in line
		stream.XORKeyStream(workingBuf[:bytesRead], workingBuf[:bytesRead])
		writer.Write(workingBuf[:bytesRead])
	}

	return nil

}

// func FileEncrypt(fileName, encExt string, key []byte) error {
// 	// this function will use stream encryption to encrypt
// 	// a file. Will throw an error if the file doesn't exist or
// 	// couldn't write or whatever.
// 	switch len(key) {
// 	case 16, 24, 32:
// 	default:
// 		return errors.New("need 16, 24, or 32 byte key length")
// 	}

// 	// open the file for reading
// 	f, err := os.Open(fileName)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()
// 	reader := bufio.NewReader(f)

// 	// now open the outfile for writing
// 	outFilename := fmt.Sprintf("%s.%s", fileName, encExt)
// 	wf, err := os.OpenFile(outFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
// 	if err != nil {
// 		return err
// 	}
// 	defer wf.Close()
// 	writer := bufio.NewWriter(wf)

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return err
// 	}

// 	iv, err := GenerateRandomBytes(aes.BlockSize)
// 	if err != nil {
// 		return err
// 	}
// 	// var out bytes.Buffer
// 	stream := cipher.NewOFB(block, iv)

// 	// write the IV to the ciphertext buffer
// 	for i := 0; i < len(iv); i++ {
// 		writer.WriteByte(iv[i])
// 	}

// 	workingBuf := make([]byte, 1024)

// 	for {
// 		bytesRead, err := reader.Read(workingBuf)
// 		if err != nil {
// 			if err == io.EOF {
// 				break
// 			} else {
// 				return err
// 			}
// 		}

// 		// now encrypt the data
// 		stream.XORKeyStream(workingBuf[:bytesRead], workingBuf[:bytesRead])

// 		_, err = writer.Write(workingBuf[:bytesRead])
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }
