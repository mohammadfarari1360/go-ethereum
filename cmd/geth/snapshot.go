// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	cli "gopkg.in/urfave/cli.v1"
)

var (
	snapshotCommand = cli.Command{
		Name:        "snapshot",
		Usage:       "A set of commands based on the snapshot",
		Category:    "MISCELLANEOUS COMMANDS",
		Description: "",
		Subcommands: []cli.Command{
			{
				Name:      "traverse-state",
				Usage:     "Traverse the state with given root hash for verification",
				ArgsUsage: "<root>",
				Action:    utils.MigrateFlags(traverseState),
				Category:  "MISCELLANEOUS COMMANDS",
				Flags: []cli.Flag{
					utils.DataDirFlag,
					utils.RopstenFlag,
					utils.RinkebyFlag,
					utils.GoerliFlag,
					utils.LegacyTestnetFlag,
				},
				Description: `
geth snapshot traverse-state <state-root>
will traverse the whole trie from the given root and will abort if any referenced
node is missing. This command can be used for trie integrity verification.
`,
			},
		},
	}
)

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// emptyCode is the known hash of the empty EVM bytecode.
	emptyCode = crypto.Keccak256(nil)
)

// traverseState is a helper function used for pruning verification.
// Basically it just iterates the trie, ensure all nodes and assoicated
// contract codes are present.
func traverseState(ctx *cli.Context) error {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(true)))
	glogger.Verbosity(log.LvlInfo)
	log.Root().SetHandler(glogger)

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, chaindb := utils.MakeChain(ctx, stack, true)
	defer chaindb.Close()

	snaptree := snapshot.New(chaindb, trie.NewDatabase(chaindb), 256, chain.CurrentBlock().Root(), false, false)
	if ctx.NArg() > 1 {
		utils.Fatalf("too many arguments given")
	}
	var root = chain.CurrentBlock().Root()
	if ctx.NArg() == 1 {
		root = common.HexToHash(ctx.Args()[0])
	}

	var (
		accounts         int
		accountsWithCode int
		slots            int
		codes            int
		lastReport       time.Time
		start            = time.Now()
	)

	acctIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer acctIt.Release()
	for acctIt.Next() {
		accounts += 1
		var acc struct {
			Nonce    uint64
			Balance  *big.Int
			Root     common.Hash
			CodeHash []byte
		}
		account, err := snapshot.FullAccountRLP(acctIt.Account())
		if err != nil {
			log.Crit("Invalid account RLP", "error", err)
		}
		if err := rlp.DecodeBytes(account, &acc); err != nil {
			log.Crit("Invalid account encountered during traversal", "error", err)
		}

		if acc.Root != emptyRoot {
			storageIt, err := snaptree.StorageIterator(root, acctIt.Hash(), common.Hash{})
			if err != nil {
				return err
			}
			defer storageIt.Release()
			for storageIt.Next() {
				slots += 32
			}
			if storageIt.Error() != nil {
				log.Crit("Failed to traverse storage trie", "root", acc.Root, "error", storageIt.Error())
			}
		}
		if !bytes.Equal(acc.CodeHash, emptyCode) {
			code := rawdb.ReadCode(chaindb, common.BytesToHash(acc.CodeHash))
			if len(code) == 0 {
				log.Crit("Code is missing", "hash", common.BytesToHash(acc.CodeHash))
			}
			accountsWithCode += 1
			codes += len(code)
		}
		if time.Since(lastReport) > time.Second*8 {
			log.Info("Traversing state", "accounts", accounts, "with code", accountsWithCode, "slots", slots, "total code size", codes, "elapsed", common.PrettyDuration(time.Since(start)))
			lastReport = time.Now()
		}
	}
	if acctIt.Error() != nil {
		log.Crit("Failed to traverse state trie", "root", root, "error", acctIt.Error())
	}

	log.Info("State is complete", "accounts", accounts, "slots", slots, "codes", codes, "elapsed", common.PrettyDuration(time.Since(start)))

	return nil
}
