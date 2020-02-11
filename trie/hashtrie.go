// Copyright 2020 The go-ethereum Authors
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
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

// HashTrie is a Merkle Patricia Trie, which can only be used for
// constructing a trie from a sequence of sorted leafs, in descending order
type HashTrie struct {
	root    node
	rootKey []byte
	build   []node
}

func NewHashTrie() *HashTrie {
	return &HashTrie{root: nil, rootKey: nil, build: nil}
}

func (t *HashTrie) TryUpdate(key, value []byte) error {
	k := keybytesToHex(key)
	if len(value) == 0 {
		panic("deletion not supported")
	}
	t.root = t.insert(t.root, nil, k, valueNode(value))
	return nil
}

func (t *HashTrie) insert(n node, prefix, key []byte, value node) node {
	if len(key) == 0 {
		return value
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, it already exists
		if matchlen == len(n.Key) {
			n.Val = t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			n.flags = nodeFlag{dirty: true}
			return n
		}

		if key[matchlen] < n.Key[matchlen] {
			panic("Keys were inserted unsorted, this should not happen")
		}

		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: nodeFlag{dirty: true}}
		hashed, _ := newHasher(false).hash(t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val), false)
		branch.Children[n.Key[matchlen]] = hashed.(hashNode)

		// Hashing the sub-node, nothing will be added to this sub-branch
		branch.Children[key[matchlen]] = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)

		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return branch
		}
		// Otherwise, replace it with a short node leading up to the branch.
		n.Key = key[:matchlen]
		n.Val = branch
		n.flags = nodeFlag{dirty: true}
		return n

	case *fullNode:
		n.flags = nodeFlag{dirty: true}
		// If any previous child wasn't already hashed, do it now since
		// the keys arrive in order, so if a branch is here then whatever
		// came before can safely be hashed.
		for i := int(key[0]) - 1; i > 0; i -= 1 {
			switch n.Children[i].(type) {
			case *shortNode, *fullNode, *valueNode:
				hashed, _ := newHasher(false).hash(n.Children[i], false)
				n.Children[i] = hashed
			// hash encountred, the rest has already been hashed
			case hashNode:
				break
			default:
				panic("invalid node")
			}
		}
		n.Children[key[0]] = t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		return n

	case nil:
		return &shortNode{key, value, nodeFlag{dirty: true}}

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet -- this means
		// someone inserted
		panic("hash resolution not supported")

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func (t *HashTrie) Hash() common.Hash {
	if t.root == nil {
		return emptyRoot
	}
	h := newHasher(false)
	defer returnHasherToPool(h)
	hashed, cached := h.hash(t.root, true)
	t.root = cached
	return common.BytesToHash(hashed.(hashNode))
}

type OneMoreTrieBit struct {
	branch fullNode
	ext    shortNode
	//inUse  bool
}

type OneMoreTrie struct {
	stack   [64]OneMoreTrieBit
	hasSome bool
}

func NewOneMoreTrie() *OneMoreTrie {
	omt := OneMoreTrie{}
	omt.stack[0].ext.Key = []byte{}
	omt.stack[0].ext.Val = &omt.stack[0].branch

	omt.stack[0].ext.Val = &omt.stack[0].branch
	return &omt
}

func (o *OneMoreTrie) TryUpdate(key, value []byte) error {
	k := keybytesToHex(key)
	//fmt.Println("key=", key)
	if len(value) == 0 {
		panic("deletion not supported")
	}
	if len(k) < 1 {
		panic("invalid key length")
	}
	//if o.stack[0].inUse {
	//o.stack[0].ext.Key = k[:len(k)-1]
	//o.stack[0].branch.Children[k[len(k)-1]] = valueNode(value)
	//o.stack[0].inUse = true
	//} else {
	o.insert(&o.stack[0].ext, nil, k, valueNode(value))
	//}
	return nil
}

func (o *OneMoreTrie) insert(n node, prefix, key []byte, value node) {
	if !o.hasSome {
		o.stack[0].ext.Key = key
		o.stack[0].ext.Val = value
		o.hasSome = true
		return
	}

	//fmt.Println("insert key=", key, "value=", value)
	// Go down the list to see where it differs
	nodeIndex := 0
	for {
		nOde := o.stack[nodeIndex]
		// Look for a common prefix. If there is at least one nibble in
		// common, then a new intermediate node needs to be created.
		whereitdiffers := 0
		for i, b := range nOde.ext.Key {
			whereitdiffers++
			// len(nOde.ext.Key) < len(key), panic if this isn't the case
			if b != key[i] {
				break
			}
		}

		// Do both extension share all nibbles?
		if whereitdiffers == len(nOde.ext.Key) {
			// At this stage, the length of the extension part is
			// the same as that of the key.

			// Check if it needs to recurse into the existing subtree,
			// or if a new one needs to be created and the existing one
			// hashed.
			switch nOde.branch.Children[key[len(nOde.ext.Key)]].(type) {
			case *hashNode:
				panic("Trying to insert in a hash node!")
			case *shortNode, *fullNode:
				// Move to the next item in the node list.
				nodeIndex++
				key = key[len(nOde.ext.Key)+1:]
			case nil:
				// Hash the previous entry (if it exits)
				// freeing its OneMoreTrieBit.
				//
				// First, look for the previous entry.
				i := key[len(nOde.ext.Key)]
				for ; i > 0 && nOde.branch.Children[i] != nil; i-- {
				}
				// If a non-nil previous entry exists, hash it.
				switch nOde.branch.Children[i].(type) {
				case *shortNode, *fullNode, *valueNode:
					hashed, _ := newHasher(false).hash(nOde.branch.Children[i], false)
					nOde.branch.Children[i] = hashed.(hashNode)
					// Go down the stack and free all entries,
					// one could try to optimize the hashing since
					// we have to go over the list to hash anyway
					//for _, noDE := range o.stack[nodeIndex:] {
					//if noDE.inUse == false {
					//break
					//}
					//noDE.inUse = false
					//}
				default:
				}

				// Advance the current index in the node list
				nodeIndex++

				// Special case: if the end of the key has been
				// reached, just place the key there.
				if whereitdiffers+1 == len(key) {
					nOde.branch.Children[key[len(key)]] = value.(valueNode)
					continue
				}

				// Look for a free spot, if none is found then
				// allocate one in the free list.
				//if len(o.stack) == nodeIndex {
				//o.stack = append(o.stack, &OneMoreTrieBit{inUse: true})
				//}

				// Initialize the reused/allocated element
				o.stack[nodeIndex].ext.Key = key[whereitdiffers+1:]
				o.stack[nodeIndex].ext.Val = &o.stack[nodeIndex].branch
				o.stack[nodeIndex].branch.Children[len(nOde.ext.Key)] = value
				//o.stack[nodeIndex].inUse = true
			default:
				panic("Invalid node type encountered")
			}
		} else {
			// Extensions differ, a new subnode is needed. One of the
			// consequences is that another, intermediate new block needs
			// to be inserted. Another consequence is that the other part
			// can immediately be hashed.

			common := nOde.ext.Key[:whereitdiffers]
			slot := nOde.ext.Key[whereitdiffers]
			nOde.ext.Key = nOde.ext.Key[whereitdiffers+1:]

			// Hash the child node to free space on the stack
			hashed, _ := newHasher(false).hash(&nOde.ext, false)

			//if len(o.stack) == nodeIndex+1 {
			//o.stack = append(o.stack, &OneMoreTrieBit{})
			//}

			// The current entry has been hashed, reuse it as the
			// parent.
			o.stack[nodeIndex].ext.Key = common
			o.stack[nodeIndex].branch.Children[slot] = hashed.(hashNode)
			o.stack[nodeIndex].branch.Children[key[whereitdiffers]] = &o.stack[nodeIndex+1].ext

			// Free the rest of the stack
			//for _, noDE := range o.stack[nodeIndex+2:] {
			//noDE.inUse = false
			//}

			// Use the next entry to place the inserted node
			//o.stack[nodeIndex+1].inUse = true
			o.stack[nodeIndex+1].ext.Key = key[whereitdiffers+1 : len(key)-1]
			o.stack[nodeIndex+1].branch.Children[key[len(key)-1]] = value
			break
		}
	}
}

func (o *OneMoreTrie) Hash() common.Hash {
	if o.hasSome == false {
		return emptyRoot
	}

	h := newHasher(false)
	defer returnHasherToPool(h)
	hashed, _ := h.hash(&o.stack[0].ext, true)
	return common.BytesToHash(hashed.(hashNode))
}
