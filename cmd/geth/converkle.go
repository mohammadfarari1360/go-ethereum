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

	"bufio"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	trieUtils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/golang/snappy"
	"github.com/holiman/uint256"
	"gopkg.in/urfave/cli.v1"
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

var IdxSize = int(unsafe.Sizeof(Index{}))

type writeBuf struct {
	file *os.File
	w    *bufio.Writer
}

func (w *writeBuf) Close() error {
	w.w.Flush()
	return w.file.Close()
}

// dumpToDisk writes elements from the given chan to file dumps.
func dumpToDisk(elemCh chan *group) error {
	var (
		id         = 0
		dataOffset = uint64(0)
		indexSize  = 0
		dataFile   *writeBuf
		indexFile  *writeBuf
		err        error
	)
	reopen := func(fname string) (*writeBuf, error) {
		f, err := os.OpenFile(fname, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		return &writeBuf{f, bufio.NewWriter(f)}, nil
	}
	if dataFile, err = reopen(fmt.Sprintf("dump-%02d.verkle", id)); err != nil {
		return err
	}
	if indexFile, err = reopen(fmt.Sprintf("index-%02d.verkle", id)); err != nil {
		dataFile.Close()
		return err
	}
	log.Info("Opened files", "data", dataFile.file.Name(), "index", indexFile.file.Name())

	for elem := range elemCh {
		idx := Index{
			Stem:   elem.stem,
			Offset: dataOffset,
		}
		{ // Writing the data
			payload, err := rlp.EncodeToBytes(elem.values)
			if err != nil {
				return err
			}
			payload = snappy.Encode(nil, payload)
			if n, err := dataFile.w.Write(payload); err != nil {
				return err
			} else {
				idx.Size = uint32(n)
				dataOffset += uint64(n)
			}
		}
		if err := binary.Write(indexFile.w, binary.LittleEndian, &idx); err != nil {
			return err
		} else {
			indexSize += IdxSize // 43
		}
		if indexSize > 2*1024*1024*1024 {
			id += 1
			indexSize = 0
			indexFile.Close()
			if indexFile, err = reopen(fmt.Sprintf("index-%02d.verkle", id)); err != nil {
				dataFile.Close()
				return err
			}
			log.Info("Opened files", "data", dataFile.file.Name(), "index", indexFile.file.Name())
		}
	}
	dataFile.Close()
	return indexFile.Close()
}

type slotHash struct {
	slot []byte
	hash common.Hash
}

func iterateSlots(slotCh chan *slotHash, storageIt snapshot.StorageIterator) {
	defer storageIt.Release()
	for storageIt.Next() {
		slotCh <- &slotHash{
			hash: storageIt.Hash(),
			slot: storageIt.Slot(),
		}
	}
	if storageIt.Error() != nil {
		log.Error("Iterating storage ended on error", "error", storageIt.Error())
	}
	close(slotCh)
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
		kvCh       = make(chan *group, 100)
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
	type accHash struct {
		account snapshot.Account
		hash    common.Hash
	}
	// accounts are pretty small, buffering 100 of them isn't a biggie
	accountCh := make(chan *accHash, 100)
	go func() {
		accIt, err := snaptree.AccountIterator(root, common.Hash{})
		if err != nil {
			panic(fmt.Sprintf("account iteration could not start: %v", err))
			//return err
		}
		defer accIt.Release()
		// Process all accounts sequentially
		for accIt.Next() {
			acc, err := snapshot.FullAccount(accIt.Account())
			if err != nil {
				panic(err)
			}
			accountCh <- &accHash{
				account: acc,
				hash:    accIt.Hash(),
			}
		}
		if accIt.Error() != nil {
			log.Error("Account iteration ended on error ", "root", root, "error", accIt.Error())
		}
		close(accountCh)
	}()

	// Process all accounts sequentially
	for accData := range accountCh {
		acc := accData.account
		accHash := accData.hash
		if time.Since(lastReport) > time.Second*8 {
			log.Info("Traversing state", "accounts", accounts, "at", accHash.String(), "elapsed", common.PrettyDuration(time.Since(start)))
			lastReport = time.Now()
		}
		if accounts == 100000 {
			log.Info("Traversing state", "accounts", accounts, "at", accHash.String(), "elapsed", common.PrettyDuration(time.Since(start)))
			lastReport = time.Now()
			break
		}
		accounts += 1

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
		stem := trieUtils.GetTreeKeyVersion(accHash.Bytes())[:]
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
			var chunkkey []byte
			for i, chunk := range chunks {
				// The chunkkey needs to be recalculated every 128th item or so,
				// or specifically whenever the subIndex toggles to zero
				if subIndex := byte((128 + i) % 256); subIndex == 0 {
					chunkkey = trieUtils.GetTreeKeyCodeChunk(accHash.Bytes(), uint64(i))
				} else {
					// Else we can just update the last byte
					nchunk := make([]byte, 32)
					copy(nchunk, chunkkey)
					nchunk[31] = subIndex
					chunkkey = nchunk
				}

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
			storageIt, err := snaptree.StorageIterator(root, accHash, common.Hash{})
			if err != nil {
				log.Error("Failed to open storage trie", "root", acc.Root, "error", err)
				return err
			}
			slotCh := make(chan *slotHash, 100)
			// TODO these aren't properly stopped in case of errors / aborts
			// TODO instead of firing up a new goroutine each time, just pass
			// the iterator to a persistent routine (which also handles aborts properly)
			go iterateSlots(slotCh, storageIt)
			for sh := range slotCh {
				if time.Since(lastReport) > time.Second*8 {
					log.Info("Traversing state", "accounts", accounts, "in", accHash.String(), "elapsed", common.PrettyDuration(time.Since(start)))
					lastReport = time.Now()
				}
				slotkey := trieUtils.GetTreeKeyStorageSlot(accHash.Bytes(), uint256.NewInt(0).SetBytes(sh.hash.Bytes()))
				var value [32]byte
				copy(value[:len(sh.slot)-1], sh.slot)

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
		}
		// Finish with storing the complete account header group
		// inside the tree.
		var st [31]byte
		copy(st[:], stem)
		kvCh <- &group{st, newValues}
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
