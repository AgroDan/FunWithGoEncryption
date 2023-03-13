package main

import (
	"feistEncrypt/encrypt"
	"fmt"
)

func main() {
	x := "Hi Christina, I am going to write this in a secret code"
	fmt.Printf("%s\n", x)

	fmt.Printf("Now encrypt it with the key \"Christina\"...\n")

	r := encrypt.FeistalEncrypt([]byte(x), []byte("Christina"), 50)

	fmt.Printf("Here: %s\n", string(r))

	out := encrypt.FeistalEncrypt(r, []byte("Christina"), 50)
	fmt.Printf("So let's decrypt: %s\n", string(out))

	fmt.Printf("Now let's encrypt this testdata file...\n")

	encrypt.FileEncrypt("testdata", "crypt", []byte("yellow submarine"))

	fmt.Printf("Look now\n")

	fmt.Printf("Now let's try and decrypt it.\n")

	encrypt.FileDecrypt("testdata.crypt", "decrypted", []byte("yellow submarine"))

	// val := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	// fmt.Printf("Take the following and jumble it: %#v\n", val)

	// res, err := encrypt.SplitBytes(val)
	// if err != nil {
	// 	fmt.Printf("What!!! %s\n", err)
	// }

	// enc := encrypt.AgroCrypt(res)

	// fmt.Printf("Now it looks like this: %#v\n", enc)
}
