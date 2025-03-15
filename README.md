# nftdesk

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/nickgarlis/nftdesk)
[![GitHub](https://img.shields.io/github/license/nickgarlis/nftdesk)](https://img.shields.io/github/license/nickgarlis/nftdesk)
[![Go Report Card](https://goreportcard.com/badge/github.com/nickgarlis/nftdesk)](https://goreportcard.com/report/github.com/nickgarlis/nftdesk)

This is a thin wrapper around Google's
[`nftables`](https://github.com/google/nftables) to simplify the programmatic
creation of nftables rules by communicating directly with netfilter.

> **Note:** This library is under development. The API might change as I tinker with the design. 🚧

## Installation

```bash
go get github.com/nickgarlis/nftdesk@v0.0.1
```

## Example Usage

```go
package main

import (
	"github.com/nickgarlis/nftdesk"
	"github.com/nickgarlis/nftdesk/expr"
	"github.com/nickgarlis/nftdesk/models"
)

func main() {
	d, err := nftdesk.NewNftDesk()
	if err != nil {
		panic(err)
	}

	table := d.AddTable("my-table", models.TableFamilyIPv4)

	chain := table.AddChain("my-chain")

	_, err = chain.AddRule(
		expr.CtStateExpr().In(expr.CtStateESTABLISHED, expr.CtStateRELATED),
		expr.VerdictExpr().OfKindAccept(),
	)
	if err != nil {
		panic(err)
	}

	err = d.Flush()
	if err != nil {
		panic(err)
	}
}
```
