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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	trieUtils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/gballet/go-verkle"
	"github.com/golang/snappy"
	lru "github.com/hashicorp/golang-lru"
	"github.com/holiman/uint256"
	"gopkg.in/urfave/cli.v1"
)

// group represents a piece of data to be stored in the verkle tree.
type group struct {
	stem   [31]byte
	values [][]byte
}

type Index struct {
	Stem   [31]byte //31
	Offset uint64   // 8
	Size   uint32   // 4 == 43
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

const (
	numTrees           = 16
	numChildrenPerTree = 256 / numTrees
)

// dumpToDisk writes elements from the given chan to file dumps.
func dumpToDisk(elemCh chan *group) error {
	var (
		dataOffset = uint64(0)
		indexSize  = 0
		dataFile   *writeBuf
		err        error
	)
	reopen := func(fname string) (*writeBuf, error) {
		f, err := os.OpenFile(fname, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		return &writeBuf{f, bufio.NewWriter(f)}, nil
	}
	if dataFile, err = reopen(fmt.Sprintf("dump-%02d.verkle", 0)); err != nil {
		return err
	}
	indexFiles := make([]*writeBuf, numTrees)
	for id := range indexFiles {
		if indexFiles[id], err = reopen(fmt.Sprintf("index-%02d.verkle", id)); err != nil {
			dataFile.Close()
			return err
		}
		log.Info("Opened files", "index", indexFiles[id].file.Name())
		defer indexFiles[id].Close()
	}
	log.Info("Opened file", "data", dataFile.file.Name())

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
		if err := binary.Write(indexFiles[idx.Stem[0]%numTrees].w, binary.LittleEndian, &idx); err != nil {
			return err
		} else {
			indexSize += IdxSize // 43
		}
	}
	dataFile.Close()
	return nil
}

type slotHash struct {
	slot []byte
	hash common.Hash
}

func iterateSlots(slotCh chan *slotHash, storageIt snapshot.StorageIterator, chaindb ethdb.Database) {
	defer storageIt.Release()
	cache, err := lru.New(1_000_000) // Keysize: 32 byte, Valuesize: 32 byte, 1M items -> 64M memory
	if err != nil {
		panic(err)
	}
	for storageIt.Next() {
		var (
			h        = storageIt.Hash()
			slot     [32]byte
			preimage common.Hash
		)
		// lookup preimage
		if v, ok := cache.Get(h); ok {
			preimage = v.(common.Hash)
		} else {
			if slotNum := rawdb.ReadPreimage(chaindb, h); len(slotNum) == 0 {
				panic(fmt.Sprintf("no preimage for %x", h.Bytes()))
			} else {
				preimage = common.BytesToHash(slotNum)
			}
			cache.Add(h, preimage)
		}
		copy(slot[:], storageIt.Slot())
		slotCh <- &slotHash{
			hash: preimage,
			slot: slot[:],
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

	go func() {
		fmt.Println(http.ListenAndServe("localhost:8080", nil))
	}()

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
		code    []byte
	}
	// accounts are pretty small, buffering 100 of them isn't a biggie
	// even with code, the max is only a couple of MB
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
			var code []byte
			if !bytes.Equal(acc.CodeHash, emptyCode) {
				code = rawdb.ReadCode(chaindb, common.BytesToHash(acc.CodeHash))
			}
			addr := rawdb.ReadPreimage(chaindb, accIt.Hash())
			if len(addr) == 0 {
				panic(fmt.Sprintf("no preimage for %x", accIt.Hash().Bytes()))
			}
			accountCh <- &accHash{
				account: acc,
				hash:    accIt.Hash(),
				code:    code,
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
		accounts += 1

		// Get the loader-routines started
		var slotCh chan *slotHash
		if !bytes.Equal(acc.Root, emptyRoot[:]) {
			storageIt, err := snaptree.StorageIterator(root, accHash, common.Hash{})
			if err != nil {
				log.Error("Failed to open storage trie", "root", acc.Root, "error", err)
				return err
			}
			slotCh = make(chan *slotHash, 100)
			// TODO these aren't properly stopped in case of errors / aborts
			// TODO instead of firing up a new goroutine each time, just pass
			// the iterator to a persistent routine (which also handles aborts properly)
			go iterateSlots(slotCh, storageIt, chaindb)
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
		stem := trieUtils.GetTreeKeyVersion(accHash.Bytes())[:]
		// Store the account code if present
		if code := accData.code; code != nil {
			binary.LittleEndian.PutUint64(codeSize[:8], uint64(len(code)))

			chunks, err := trie.ChunkifyCode(code)
			if err != nil {
				panic(err)
			}

			// Store all the chunks belonging to the header group
			for i := 0; i < 128 && i < len(chunks); i++ {
				newValues[128+i] = chunks[i][:]
			}

			// Store the following groups
			for i := 128; i < len(chunks); {
				values := make([][]byte, 256)
				chunkkey := trieUtils.GetTreeKeyCodeChunk(accHash[:], uint64(i))
				j := i
				for ; (j-i) < 256 && j < len(chunks); j++ {

					values[(j-128)%256] = chunks[j][:]
				}
				i = j

				// Otherwise, store the previous group in the tree with a
				// stem insertion.
				g := &group{values: values}
				copy(g.stem[:], chunkkey[:31])
				kvCh <- g
			}
		}

		// Save every slot into the tree
		if slotCh != nil {
			var (
				laststem  [31]byte
				values    = make([][]byte, 256)
				addrpoint = trieUtils.EvaluateAddressPoint(accHash.Bytes())
			)
			copy(laststem[:], stem)
			for sh := range slotCh {
				if time.Since(lastReport) > time.Second*8 {
					log.Info("Traversing state", "accounts", accounts, "in", accHash.String(), "elapsed", common.PrettyDuration(time.Since(start)))
					lastReport = time.Now()
				}
				slotkey := trieUtils.GetTreeKeyStorageSlotWithEvaluatedAddress(addrpoint, uint256.NewInt(0).SetBytes(sh.hash.Bytes()))
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

				// flush the previous group, iff it's not the header group
				if !bytes.Equal(stem[:31], laststem[:]) {
					kvCh <- &group{stem: laststem, values: values[:]}
				}

				values = make([][]byte, 256)
				values[slotkey[31]] = value[:]
				copy(laststem[:], slotkey[:31])
			}

			// commit the last group if it's not the header group
			if !bytes.Equal(laststem[:31], stem[:31]) {
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
	dataFile, err := os.Open("dump-00.verkle")
	if err != nil {
		return err
	}
	outFile, err := os.OpenFile("dump-01.verkle", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()
	outBuf := bufio.NewWriter(outFile)
	var dataOffset uint64

	for id := 0; ; id++ {
		idxFile := fmt.Sprintf("index-%02d.verkle", id)
		if _, err := os.Stat(idxFile); err != nil {
			break
		}
		outIdxFile, err := os.OpenFile("sorted-"+idxFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer outIdxFile.Close()
		outIdxBuf := bufio.NewWriter(outIdxFile)

		log.Info("Processing indexfile", "name", idxFile)
		data, err := os.ReadFile(idxFile)
		if err != nil {
			return err
		}
		log.Info("Read file", "name", idxFile)
		// Sort the data
		sort.Sort(dataSort(data))
		log.Info("Sorted file", "name", idxFile)

		buf := bytes.NewBuffer(data)
		var idx Index
		err = binary.Read(buf, binary.LittleEndian, &idx)
		for err != io.EOF {
			// Read the data
			valuesSerializedCompressed := make([]byte, idx.Size)
			var n int
			n, err = dataFile.ReadAt(valuesSerializedCompressed, int64(idx.Offset))
			if err != nil {
				return fmt.Errorf("error reading data: %w size=%d != %d", err, n, idx.Size)
			}
			data, err := snappy.Decode(nil, valuesSerializedCompressed)
			if err != nil {
				return fmt.Errorf("error decompressing data: %w", err)
			}
			var element group
			rlp.DecodeBytes(data, &element.values)

			var index Index
			err = binary.Read(buf, binary.LittleEndian, &index)

			// Merge all consecutive values
			for bytes.Equal(index.Stem[:], idx.Stem[:]) {
				compressed := make([]byte, index.Size)
				_, err = dataFile.ReadAt(compressed, int64(index.Offset))
				if err != nil {
					return err
				}
				d, e := snappy.Decode(nil, compressed)
				if e != nil {
					return e
				}
				var vals [][]byte
				rlp.DecodeBytes(d, vals)

				for i, v := range vals {
					if len(v) == 0 {
						if len(element.values[i]) == 0 {
							element.values[i] = vals[i]
						} else {
							return fmt.Errorf("value being overwritten at %x", index.Stem)
						}
					}
				}

				err = binary.Read(buf, binary.LittleEndian, &index)
			}

			idx.Offset = dataOffset
			binary.Write(outIdxBuf, binary.LittleEndian, idx)
			payload, e := rlp.EncodeToBytes(element.values)
			if e != nil {
				return e
			}
			payload = snappy.Encode(nil, payload)
			idx.Size = uint32(len(payload))
			dataOffset += uint64(idx.Size)
			outBuf.Write(payload)
			idx = index
		}

		os.WriteFile(idxFile, data, 0600)
		log.Info("Wrote file", "name", idxFile)
	}
	return nil
}

func readDataDump(itemCh chan group, abortCh chan struct{}, cpuNumber int) error {
	dataFile, err := os.Open("dump-00.verkle")
	if err != nil {
		return err
	}
	defer dataFile.Close()

	// open all the files and read the first record of each
	idxFile, err := os.Open(fmt.Sprintf("index-%02d.verkle", cpuNumber))
	if err != nil {
		return err
	}
	defer idxFile.Close()
	var idx Index
	err = binary.Read(idxFile, binary.LittleEndian, &idx)
	for err != io.EOF {
		dataFile.Seek(int64(idx.Offset), io.SeekStart)
		valuesSerializedCompressed := make([]byte, idx.Size)
		n, err := dataFile.Read(valuesSerializedCompressed)
		if err != nil || uint32(n) != idx.Size {
			return fmt.Errorf("error reading data: %w size=%d != %d", err, n, idx.Size)
		}
		data, err := snappy.Decode(nil, valuesSerializedCompressed)
		var element group
		rlp.DecodeBytes(data, &element.values)

		copy(element.stem[:], idx.Stem[:])
		// pass the data
		itemCh <- element
		// read next index
		err = binary.Read(idxFile, binary.LittleEndian, &idx)

		select {
		case <-abortCh:
			return nil
		default:
			continue
		}

	}
	return nil
}

func doInsertion(ctx *cli.Context) error {

	var (
		start      = time.Now()
		lastReport time.Time
		itemChs    = make([]chan group, runtime.NumCPU())
		abortCh    = make(chan struct{})
		wg         sync.WaitGroup
		count      = uint64(0)
	)
	defer close(abortCh)
	wg.Add(runtime.NumCPU())
	for numCPU := range itemChs {
		itemChs[numCPU] = make(chan group, 1000)
		itemCh := itemChs[numCPU]
		i := numCPU
		go func() {
			defer wg.Done()
			if err := readDataDump(itemCh, abortCh, i); err != nil {
				log.Error("Error reading data", "err", err)
			}
			close(itemCh)
		}()
	}

	convdb, err := rawdb.NewLevelDBDatabase("verkle", 128, 128, "", false)
	if err != nil {
		return err
	}

	flushCh := make(chan verkle.VerkleNode)
	saveverkle := func(node verkle.VerkleNode) {
		flushCh <- node
	}
	go func() {
		for node := range flushCh {
			comm := node.ComputeCommitment()
			s, err := node.Serialize()
			if err != nil {
				panic(err)
			}
			commB := comm.Bytes()
			if err := convdb.Put(commB[:], s); err != nil {
				panic(err)
			}
		}
	}()

	subRoots := make([]*verkle.InternalNode, runtime.NumCPU())
	for i := range itemChs {
		wg.Add(1)
		subRoots[i] = verkle.New().(*verkle.InternalNode)

		// save references for the goroutine to capture
		root := subRoots[i]
		itemCh := itemChs[i]

		go func() {
			for elem := range itemCh {
				var st = make([]byte, 31)
				copy(st, elem.stem[:])
				leaf := verkle.NewLeafNode(st, elem.values)
				leaf.ComputeCommitment()
				err = root.InsertStemOrdered(st, leaf, saveverkle)
				if err != nil {
					panic(err)
				}
				atomic.AddUint64(&count, 1)
				if time.Since(lastReport) > time.Second*8 {
					log.Info("Traversing state", "count", count, "elapsed", common.PrettyDuration(time.Since(start)))
					lastReport = time.Now()
				}
			}

			wg.Done()
		}()
	}
	wg.Wait()
	root := verkle.MergeTrees(subRoots)
	root.ComputeCommitment()
	root.(*verkle.InternalNode).Flush(saveverkle)
	close(flushCh)
	log.Info("Insertion done", "elems", count, "root commitment", fmt.Sprintf("%x", root.ComputeCommitment().Bytes()), "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}
