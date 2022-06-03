// Copyright 2022 go-ethereum Authors
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

package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

type VerkleBridgeTrie struct {
	mpt            *Trie
	verkle         *VerkleBridgeTrie
	isTransitioned bool
}

func NewBridgeTrie(db *Database, isTransitioned bool, root common.Hash) *VerkleBridgeTrie {
	var err error

	ret := &VerkleBridgeTrie{
		isTransitioned: isTransitioned,
	}

	if isTransitioned {
		ret.mpt, err = New(frozenRoot, db)
		ret.verkle = NewVerkleTrie(root, db)
	} else {
		ret.mpt, err = New(root, db)
	}

	if err != nil {
		panic(err)
	}

	return ret
}

func (trie *VerkleBridgeTrie) TryGet(key []byte) ([]byte, error) {
	var (
		val []byte
		err error
	)

	if trie.isTransitioned {
		val, err = trie.verkle.TryGet(key)

		if err != nil {
			return nil, err
		}
	}

	if val != nil {
		val, err = trie.mpt.TryGet(key)
	}

	return val, err
}

func (trie *VerkleBridgeTrie) TryUpdateAccount(key []byte, acc *types.StateAccount) error {
	if trie.isTransitioned {
		return trie.verkle.TryUpdateAccount(key, acc)
		// TODO delete data from the MPT if that is an option
	}

	return trie.mpt.TryUpdateAccount(key, acc)
}

func (trie *VerkleBridgeTrie) TryUpdate(key, value []byte) error {
	if !trie.isTransitioned {
		return trie.mpt.TryUpdate(key, value)
	}
	// TODO delete data from the MPT if that is an option
	return trie.verkle.TryUpdate(key, value)
}

func (trie *VerkleBridgeTrie) TryDelete(key []byte) error {
	if !trie.isTransitioned {
		return trie.mpt.TryDelete(key)
	}
	// TODO delete data from the MPT if that is an option
	return trie.verkle.TryDelete(key)
}

func (trie *VerkleBridgeTrie) Hash() common.Hash {
	if !trie.isTransitioned {
		return trie.mpt.Hash()
	}
	return trie.verkle.Hash()
}

func (trie *VerkleBridgeTrie) Commit(onleaf LeafCallback) (common.Hash, int, error) {
	if !trie.isTransitioned {
		return trie.mpt.Commit(onleaf)
	}
	return trie.verkle.Commit(onleaf)
}

func (trie *VerkleBridgeTrie) Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error {
	if !trie.isTransitioned {
		return trie.mpt.Prove(key, fromLevel, proofDb)
	}
	return trie.verkle.Prove(key, fromLevel, proofDb)
}

func (trie *VerkleBridgeTrie) IsVerkle() bool {
	return trie.isTransitioned
}
