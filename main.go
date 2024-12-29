package main

import (
	"flag"

	_ "github.com/p4gefau1t/trojan-go-thin/component"
	"github.com/p4gefau1t/trojan-go-thin/log"
	"github.com/p4gefau1t/trojan-go-thin/option"
)

func main() {
	flag.Parse()
	for {
		h, err := option.PopOptionHandler()
		if err != nil {
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil {
			break
		}
	}
}
