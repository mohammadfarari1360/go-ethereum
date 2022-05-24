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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	trieUtils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
	"gopkg.in/urfave/cli.v1"
)

type kv struct {
	key []byte
	val []byte
}

func dumpToDisk(elemCh chan *kv) error {
	id := 0
	size := 0
	f, err := os.OpenFile(fmt.Sprintf("dump-%02d.verkle", id), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	log.Info("Opened dumpfile", "name", f.Name())

	for elem := range elemCh {
		data := fmt.Sprintf("klen %d %x\nvlen %d %x\n", len(elem.key), elem.key, len(elem.val), elem.val)
		n, err := f.Write([]byte(data))
		if err != nil {
			f.Close()
			return err
		}
		size += n
		if size > 2*1024*1024*1024 {
			f.Close()
			id += 1
			log.Info("Opened dumpfile", "name", f.Name())
			f, err = os.OpenFile(fmt.Sprintf("dump-%02d.verkle", id), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			log.Info("Opened dumpfile", "name", f.Name())
		}
	}
	return f.Close()
}

func convertToVerkle(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, true)
	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		log.Error("Failed to load head block")
		return errors.New("no head block")
	}
	if ctx.NArg() > 1 {
		log.Error("Too many arguments given")
		return errors.New("too many arguments")
	}
	var (
		root common.Hash
		err  error
	)
	if ctx.NArg() == 1 {
		root, err = parseRoot(ctx.Args()[0])
		if err != nil {
			log.Error("Failed to resolve state root", "error", err)
			return err
		}
		log.Info("Start traversing the state", "root", root)
	} else {
		root = headBlock.Root()
		log.Info("Start traversing the state", "root", root, "number", headBlock.NumberU64())
	}
	var (
		accounts   int
		lastReport time.Time
		start      = time.Now()
		wg         sync.WaitGroup
		kvCh       = make(chan *kv, 1000)
	)
	wg.Add(1)
	go func() {
		dumpToDisk(kvCh)
		wg.Done()
	}()

	defer close(kvCh)

	//vRoot := verkle.New()
	snaptree, err := snapshot.New(chaindb, trie.NewDatabase(chaindb), 256, root, false, false, false)
	if err != nil {
		return err
	}
	accIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer accIt.Release()

	// Loop over and over the tree and flush everything that is deeper
	// than 2 nodes.
	done := make(chan struct{})
	defer func() { done <- struct{}{} }()

	// Process all accounts sequentially
	for accIt.Next() {
		accounts += 1
		acc, err := snapshot.FullAccount(accIt.Account())
		if err != nil {
			log.Error("Invalid account encountered during traversal", "error", err)
			return err
		}

		// Store the basic account data
		var (
			nonce, balance, version [32]byte
			newValues               = make([][]byte, 256)
		)
		newValues[0] = version[:]
		newValues[1] = balance[:]
		newValues[2] = nonce[:]
		newValues[4] = version[:] // memory-saving trick: by default, an account has 0 size
		binary.LittleEndian.PutUint64(nonce[:8], acc.Nonce)

		for i, b := range acc.Balance.Bytes() {
			balance[len(acc.Balance.Bytes())-1-i] = b
		}
		// XXX use preimages, accIter is the hash of the address
		stem := trieUtils.GetTreeKeyVersion(accIt.Hash().Bytes())[:]

		// Store the account code if present
		if !bytes.Equal(acc.CodeHash, emptyCode) {
			var (
				laststem [31]byte
				values   = make([][]byte, 256)
			)
			copy(laststem[:], stem)

			code := rawdb.ReadCode(chaindb, common.BytesToHash(acc.CodeHash))
			chunks, err := trie.ChunkifyCode(code)
			if err != nil {
				panic(err)
			}
			for i, chunk := range chunks {
				chunkkey := trieUtils.GetTreeKeyCodeChunk(accIt.Hash().Bytes(), uint256.NewInt(uint64(i)))
				// if the chunk belongs to the header group, store it there
				if bytes.Equal(chunkkey[:31], stem) {
					newValues[int(chunkkey[31])] = chunk[:]
					continue
				}

				// if the chunk belongs to the same group as the previous
				// one, add it to the list of values to be inserted in one
				// go.
				if bytes.Equal(laststem[:], chunkkey[:31]) {
					values[chunkkey[31]] = chunk[:]
					continue
				}

				// Otherwise, store the previous group in the tree with a
				// stem insertion.
				//err = vRoot.(*verkle.InternalNode).InsertStem(laststem[:], values, convdb.Get)
				//if err != nil {
				//	panic(err)
				//}
				// TODO, ship it off to disk

				values = make([][]byte, 256)
				values[chunkkey[31]] = chunk[:]
				copy(laststem[:], chunkkey[:31])
			}

			// Write the code size in the account header group
			var size [32]byte
			newValues[4] = size[:]
			binary.LittleEndian.PutUint64(size[:8], uint64(len(code)))
		}

		// Save every slot into the tree
		if !bytes.Equal(acc.Root, emptyRoot[:]) {
			storageIt, err := snaptree.StorageIterator(root, accIt.Hash(), common.Hash{})
			if err != nil {
				log.Error("Failed to open storage trie", "root", acc.Root, "error", err)
				return err
			}
			for storageIt.Next() {
				slotkey := trieUtils.GetTreeKeyStorageSlot(accIt.Hash().Bytes(), uint256.NewInt(0).SetBytes(storageIt.Hash().Bytes()))
				var value [32]byte
				copy(value[:len(storageIt.Slot())-1], storageIt.Slot())
				// if the slot belongs to the header group, store it there
				if bytes.Equal(slotkey[:31], stem) {
					newValues[int(slotkey[31])] = value[:]
					continue
				}
				// XXX use preimages, accIter is the hash of the address
				//err = vRoot.Insert(slotkey, value[:], convdb.Get)
				kvCh <- &kv{slotkey, value[:]}
			}

			if storageIt.Error() != nil {
				log.Error("Failed to traverse storage trie", "root", acc.Root, "error", storageIt.Error())
				return storageIt.Error()
			}
			storageIt.Release()

			// Finish with storing the complete account header group
			// inside the tree.
			//err = vRoot.(*verkle.InternalNode).InsertStem(stem, newValues, convdb.Get)
			// TODO, ship it off to disk

			if err != nil {
				panic(err)
			}
		}

		if time.Since(lastReport) > time.Second*8 {
			log.Info("Traversing state", "accounts", accounts, "elapsed", common.PrettyDuration(time.Since(start)))
			lastReport = time.Now()
		}
	}
	if accIt.Error() != nil {
		log.Error("Failed to compute commitment", "root", root, "error", accIt.Error())
		return accIt.Error()
	}
	log.Info("Disk dump ", "accounts", accounts, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}
