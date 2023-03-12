package main

import (
	"feistEncrypt/encrypt"
	"fmt"
)

func main() {
	// x := "Hello World"
	// fmt.Printf("%s\n", x)

	// fmt.Printf("Now encrypt it with the key \"slag\"...\n")

	// r := encrypt.FeistalEncrypt([]byte(x), "slag", 50)

	// fmt.Printf("Here: %s\n", string(r))

	// out := encrypt.FeistalEncrypt(r, "slag", 50)
	// fmt.Printf("So let's decrypt I guess: %s\n", string(out))

	val := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	fmt.Printf("Take the following and jumble it: %#v\n", val)

	res, err := encrypt.SplitBytes(val)
	if err != nil {
		fmt.Printf("What!!! %s\n", err)
	}

	enc := encrypt.AgroCrypt(res)

	fmt.Printf("Now it looks like this: %#v\n", enc)
}
