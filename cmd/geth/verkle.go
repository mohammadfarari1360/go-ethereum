// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/urfave/cli/v2"
)

var verkleCommand = &cli.Command{
	Name:  "verkle",
	Usage: "A set of verkle tree-related commands",
	Subcommands: []*cli.Command{
		{
			Name:      "replay",
			Usage:     "replays a series of blocks on top of a converted verkle chain",
			ArgsUsage: "<root>",
			Action:    verkleReplay,
			Flags:     utils.GroupFlags(utils.NetworkFlags, utils.DatabasePathFlags),
		},
	},
}

func verkleReplay(ctx *cli.Context) error {
	if ctx.Args().Len() != 0 {
		utils.Fatalf("This command requires an argument.")
	}

	// XXX verkle in config?
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, chainDb := utils.MakeChain(ctx, stack)

	// Check that the conversion has happened
	converted, err := chainDb.Get([]byte("verkle-convertion"))
	if err != nil {
		return fmt.Errorf("error finding conversion key in db: %w", err)
	}
	if len(converted) < 1 || converted[0] < 1 {
		return fmt.Errorf("conversion didn't complete: %x", converted)
	}

	// Insert all new blocks
	_, err = chain.InsertChain([]*types.Block{})
	return err
}
