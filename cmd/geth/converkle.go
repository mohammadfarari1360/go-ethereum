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
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	trieUtils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
	"gopkg.in/urfave/cli.v1"
	"reflect"
	"unsafe"
)

// group represents a piece of data to be stored in the verkle tree.
type group struct {
	stem   [31]byte
	values [][]byte
}

type Index struct {
	Stem   [31]byte
	Offset uint64
	Size   uint32
}

var IdxSize = unsafe.Sizeof(Index{})

// dumpToDisk writes elements from the given chan to file dumps.
func dumpToDisk(elemCh chan *group) error {
	var (
		id         = 0
		dataOffset = uint64(0)
		indexSize  = 0
		dataFile   *os.File
		indexFile  *os.File
		err        error
	)
	if dataFile, err = os.OpenFile(fmt.Sprintf("dump-%02d.verkle", id), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		return err
	}
	if indexFile, err = os.OpenFile(fmt.Sprintf("index-%02d.verkle", id), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		dataFile.Close()
		return err
	}
	log.Info("Opened files", "data", dataFile.Name(), "index", indexFile.Name())

	for elem := range elemCh {
		idx := Index{
			Stem:   elem.stem,
			Offset: dataOffset,
		}
		if payload, err := rlp.EncodeToBytes(elem.values); err != nil {
			return err
		} else if n, err := dataFile.Write(payload); err != nil {
			return err
		} else {
			idx.Size = uint32(n)
			dataOffset += uint64(n)
		}
		if err := binary.Write(indexFile, binary.LittleEndian, &idx); err != nil {
			return err
		} else {
			indexSize += IdxSize // 43
		}
		if indexSize > 2*1024*1024*1024 {
			id += 1
			indexSize = 0
			indexFile.Close()
			if indexFile, err = os.OpenFile(fmt.Sprintf("index-%02d.verkle", id), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
				dataFile.Close()
				return err
			}
			log.Info("Opened files", "data", dataFile.Name(), "index", indexFile.Name())
		}
	}
	dataFile.Close()
	return indexFile.Close()
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
		kvCh       = make(chan *group, 1)
	)
	wg.Add(1)
	go func() {
		if err := dumpToDisk(kvCh); err != nil {
			panic(err)
		}
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
			newValues                         = make([][]byte, 256)
		)
		bal := acc.Balance.Bytes()
		for i, b := range bal {
			balance[len(bal)-1-i] = b
		}
		binary.LittleEndian.PutUint64(nonce[:8], acc.Nonce)
		newValues[0] = version[:]
		newValues[1] = balance[:]
		newValues[2] = nonce[:]
		newValues[4] = codeSize[:]

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
			binary.LittleEndian.PutUint64(codeSize[:8], uint64(len(code)))

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
				kvCh <- &group{laststem, values}

				values = make([][]byte, 256)
				values[chunkkey[31]] = chunk[:]
				copy(laststem[:], chunkkey[:31])
			}
		}

		// Save every slot into the tree
		if !bytes.Equal(acc.Root, emptyRoot[:]) {
			var (
				laststem [31]byte
				values   = make([][]byte, 256)
			)
			copy(laststem[:], stem)

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

				// if the slot belongs to the same group as the previous
				// one, add it to the current group of values.
				if bytes.Equal(laststem[:], slotkey[:31]) {
					values[slotkey[31]] = value[:]
					continue
				}
				kvCh <- &group{laststem, values[:]}
			}

			if storageIt.Error() != nil {
				log.Error("Failed to traverse storage trie", "root", acc.Root, "error", storageIt.Error())
				return storageIt.Error()
			}
			storageIt.Release()
		}
		// Finish with storing the complete account header group
		// inside the tree.
		var st [31]byte
		copy(st[:], stem)
		kvCh <- &group{st, newValues}
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

const (
	keySize  = 31
	elemSize = keySize + 8 + 4
)

type dataSort []byte

func (d dataSort) Len() int {
	return len(d) / elemSize
}
func (d dataSort) Less(i, j int) bool {
	keyA := d[i*elemSize : i*elemSize+keySize]
	keyB := d[j*elemSize : j*elemSize+keySize]
	if bytes.Compare(keyA, keyB) == -1 {
		return true
	}
	return false
}

func (d dataSort) Swap(i, j int) {
	var tmp [elemSize]byte
	copy(tmp[:], d[i*elemSize:(i+1)*elemSize])
	copy(d[i*elemSize:(i+1)*elemSize], d[j*elemSize:(j+1)*elemSize])
	copy(d[j*elemSize:(j+1)*elemSize], tmp[:])
}

// doFileSorting sorts the index file.
func doFileSorting(ctx *cli.Context) error {

	indexName := fmt.Sprintf("index-%02d.verkle", 0)
	if _, err := os.Stat(indexName); err != nil {
		// Create some files.
		log.Info("Writing dummy files")
		data := make([]byte, 500000*unsafe.Sizeof(Index{}))
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
	}
	//else {
	// File(s) exist, use those
	//}

	return sortFiles()
}

func sortFiles() error {
	for id := 0; ; id++ {
		idxFile := fmt.Sprintf("index-%02d.verkle", id)
		if _, err := os.Stat(idxFile); err != nil {
			return err
		}
		log.Info("Processing indexfile", "name", idxFile)
		data, err := os.ReadFile(idxFile)
		if err != nil {
			return err
		}
		log.Info("Read file", "name", idxFile)
		// Sort the data
		sort.Sort(dataSort(data))
		log.Info("Sorted file", "name", idxFile)
		os.WriteFile(idxFile, data, 0600)
		log.Info("Wrote file", "name", idxFile)
	}
	return nil
}
