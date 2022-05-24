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
	"math/rand"
	"os"
	"sort"
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
		//data := fmt.Sprintf("klen %d %x\nvlen %d %x\n", len(elem.key), elem.key, len(elem.val), elem.val)
		//fmt.Printf(data)
		if n, err := f.Write([]byte(elem.key)); err != nil {
			f.Close()
			return err
		} else {
			size += n
		}
		if n, err := f.Write([]byte(elem.val)); err != nil {
			f.Close()
			return err
		} else {
			size += n
		}

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

	snaptree, err := snapshot.New(chaindb, trie.NewDatabase(chaindb), 256, root, false, false, false)
	if err != nil {
		return err
	}
	accIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer accIt.Release()

	store := func(k, v []byte) {
		key := make([]byte, 32)
		copy(key, k)
		value := make([]byte, 32)
		copy(value, v[:])

		kvCh <- &kv{key, value}
	}

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
			nonce, balance, version, codeSize [32]byte
		)
		binary.LittleEndian.PutUint64(nonce[:8], acc.Nonce)
		bal := acc.Balance.Bytes()
		for i, b := range bal {
			balance[len(bal)-1-i] = b
		}
		// XXX use preimages, accIter is the hash of the address
		stem := trieUtils.GetTreeKeyVersion(accIt.Hash().Bytes())[:]

		store(append(stem[:31], 0), version[:])
		store(append(stem[:31], 1), balance[:])
		store(append(stem[:31], 2), nonce[:])

		// Store the account code if present
		if !bytes.Equal(acc.CodeHash, emptyCode) {
			code := rawdb.ReadCode(chaindb, common.BytesToHash(acc.CodeHash))
			binary.LittleEndian.PutUint64(codeSize[:8], uint64(len(code)))

			chunks, err := trie.ChunkifyCode(code)
			if err != nil {
				panic(err)
			}
			for i, chunk := range chunks {
				chunkkey := trieUtils.GetTreeKeyCodeChunk(accIt.Hash().Bytes(), uint256.NewInt(uint64(i)))
				store(chunkkey, chunk[:])
			}
		}
		store(append(stem[:31], 4), codeSize[:])
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
				//if bytes.Equal(slotkey[:31], stem) {
				//	newValues[int(slotkey[31])] = value[:]
				//	continue
				//}
				// XXX use preimages, accIter is the hash of the address
				//err = vRoot.Insert(slotkey, value[:], convdb.Get)
				store(slotkey, value[:])
			}

			if storageIt.Error() != nil {
				log.Error("Failed to traverse storage trie", "root", acc.Root, "error", storageIt.Error())
				return storageIt.Error()
			}
			storageIt.Release()

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
	close(kvCh)
	wg.Wait()
	return nil
}

type dataSort []byte

func (d dataSort) Len() int {
	return len(d) / 64
}

func (d dataSort) Less(i, j int) bool {

	keyA := d[i*64 : i*64+32]
	keyB := d[j*64 : j*64+32]
	if bytes.Compare(keyA, keyB) == -1 {
		return true
	}
	return false
}

func (d dataSort) Swap(i, j int) {
	var tmp [64]byte
	copy(tmp[:], d[i*64:(i+1)*64])
	copy(d[i*64:(i+1)*64], d[j*64:(j+1)*64])
	copy(d[j*64:(j+1)*64], tmp[:])
}

// doFileSorting is a DUMMY DEBUG method which just blindly writes
// random data into 2GB-sized files, and then sorts it.
func doFileSorting(ctx *cli.Context) error {
	// Create some files.
	log.Info("Writing dummy files")
	data := make([]byte, 2*1024*1024*1024)
	for id := 0; id < 3; id++ {
		fName := fmt.Sprintf("dump-%02d.verkle", id)
		if _, err := rand.Read(data); err != nil {
			return err
		}
		if err := os.WriteFile(fName, data, 0600); err != nil {
			return err
		}
	}
	log.Info("Wrote files, now for sorting them")
	return sortFiles()
}

func sortFiles() error {
	for id := 0; ; id++ {
		fName := fmt.Sprintf("dump-%02d.verkle", id)
		if _, err := os.Stat(fName); err != nil {
			break
		}
		log.Info("Processing dumpfile", "name", fName)
		data, err := os.ReadFile(fName)
		if err != nil {
			return err
		}
		log.Info("Read file", "name", fName)
		// Sort the data
		sort.Sort(dataSort(data))
		log.Info("Sorted file", "name", fName)
		os.WriteFile(fName, data, 0600)
		log.Info("Wrote file", "name", fName)
	}
	return nil
}
