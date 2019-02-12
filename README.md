
# eciesgo

![Go](https://github.com/ecies/go/actions/workflows/go.yml/badge.svg)
[![GoDoc Widget](https://godoc.org/github.com/ecies/go?status.svg)](https://godoc.org/github.com/ecies/go)
[![Go Report](https://goreportcard.com/badge/github.com/ecies/go)](https://goreportcard.com/report/github.com/ecies/go)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with **minimal** dependencies.

This is the Go version of [ecies/py](https://github.com/ecies/py) with a built-in class-like secp256k1 API, you may go there for detailed documentation of the mechanism under the hood.

## Install
`go get github.com/ecies/go/v2`

Go 1.13 is required cause `fmt.Errorf` is used to wrap errors.

> ⚠️ Please use version 2.0.3 and later. It's much faster and safer.

## Quick Start
```go
package main

import (
	ecies "github.com/ecies/go/v2"
	"log"
)

func main() {
	k, err := ecies.GenerateKey()