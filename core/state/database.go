// Copyright 2017 The go-ethereum Authors
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

package state

import (
	"errors"
	"fmt"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/gballet/go-verkle"
	lru "github.com/hashicorp/golang-lru"
)

const (
	// Number of codehash->size associations to keep.
	codeSizeCacheSize = 100000

	// Cache size granted for caching clean code.
	codeCacheSize = 64 * 1024 * 1024
)

// Database wraps access to tries and contract code.
type Database interface {
	// OpenTrie opens the main account trie.
	OpenTrie(root common.Hash) (Trie, error)

	// OpenStorageTrie opens the storage trie of an account.
	OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash, main Trie) (Trie, error)

	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(Trie) Trie

	// ContractCode retrieves a particular contract's code.
	ContractCode(addrHash, codeHash common.Hash) ([]byte, error)

	// ContractCodeSize retrieves a particular contracts code's size.
	ContractCodeSize(addrHash, codeHash common.Hash) (int, error)

	// DiskDB returns the underlying key-value disk database.
	DiskDB() ethdb.KeyValueStore

	// TrieDB retrieves the low level trie database used for data storage.
	TrieDB() *trie.Database
}

// Trie is a Ethereum Merkle Patricia trie.
type Trie interface {
	// GetKey returns the sha3 preimage of a hashed key that was previously used
	// to store a value.
	//
	// TODO(fjl): remove this when StateTrie is removed
	GetKey([]byte) []byte

	// TryGet returns the value for key stored in the trie. The value bytes must
	// not be modified by the caller. If a node was not found in the database, a
	// trie.MissingNodeError is returned.
	TryGet(address, key []byte) ([]byte, error)

	// TryGetAccount abstract an account read from the trie.
	TryGetAccount(key []byte) (*types.StateAccount, error)

	// TryUpdate associates key with value in the trie. If value has length zero, any
	// existing value is deleted from the trie. The value bytes must not be modified
	// by the caller while they are stored in the trie. If a node was not found in the
	// database, a trie.MissingNodeError is returned.
	TryUpdate(address, key, value []byte) error

	// TryUpdateAccount abstract an account write to the trie.
	TryUpdateAccount(key []byte, account *types.StateAccount) error

	// TryDelete removes any existing value for key from the trie. If a node was not
	// found in the database, a trie.MissingNodeError is returned.
	TryDelete(address, key []byte) error

	// TryDeleteAccount abstracts an account deletion from the trie.
	TryDeleteAccount(key []byte) error

	// Hash returns the root hash of the trie. It does not write to the database and
	// can be used even if the trie doesn't have one.
	Hash() common.Hash

	// Commit collects all dirty nodes in the trie and replace them with the
	// corresponding node hash. All collected nodes(including dirty leaves if
	// collectLeaf is true) will be encapsulated into a nodeset for return.
	// The returned nodeset can be nil if the trie is clean(nothing to commit).
	// Once the trie is committed, it's not usable anymore. A new trie must
	// be created with new root and updated trie database for following usage
	Commit(collectLeaf bool) (common.Hash, *trie.NodeSet, error)

	// NodeIterator returns an iterator that returns nodes of the trie. Iteration
	// starts at the key after the given start key.
	NodeIterator(startKey []byte) trie.NodeIterator

	// Prove constructs a Merkle proof for key. The result contains all encoded nodes
	// on the path to the value at key. The value itself is also included in the last
	// node and can be retrieved by verifying the proof.
	//
	// If the trie does not contain a value for key, the returned proof contains all
	// nodes of the longest existing prefix of the key (at least the root), ending
	// with the node that proves the absence of the key.
	Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error

	// IsVerkle returns true if the trie is verkle-tree based
	IsVerkle() bool
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use, but does not retain any recent trie nodes in memory. To keep some
// historical state in memory, use the NewDatabaseWithConfig constructor.
func NewDatabase(db ethdb.Database) Database {
	return NewDatabaseWithConfig(db, nil)
}

// NewDatabaseWithConfig creates a backing store for state. The returned database
// is safe for concurrent use and retains a lot of collapsed RLP trie nodes in a
// large memory cache.
func NewDatabaseWithConfig(db ethdb.Database, config *trie.Config) Database {
	csc, _ := lru.New(codeSizeCacheSize)
	return &ForkingDB{
		cachingDB: &cachingDB{
			db:            trie.NewDatabaseWithConfig(db, config),
			disk:          db,
			codeSizeCache: csc,
			codeCache:     fastcache.New(codeCacheSize),
		},
		VerkleDB: &VerkleDB{
			db:            trie.NewDatabaseWithConfig(db, config),
			diskdb:        db,
			codeSizeCache: csc,
			codeCache:     fastcache.New(codeCacheSize),
			addrToPoint:   utils.NewPointCache(),
		},
		started: (config != nil && config.UseVerkle),
		ended:   (config != nil && config.UseVerkle),
	}
}

// ForkingDB is an adapter object to support forks between
// cachingDB and VerkleDB.
type ForkingDB struct {
	*cachingDB
	*VerkleDB

	started, ended  bool
	translatedRoots map[common.Hash]common.Hash // hash of the translated root, for opening

	// TODO ensure that this info is in the DB
	LastAccHash  common.Hash
	LastSlotHash common.Hash
}

// ContractCode implements Database
func (fdb *ForkingDB) ContractCode(addrHash common.Hash, codeHash common.Hash) ([]byte, error) {
	if fdb.started {
		return fdb.VerkleDB.ContractCode(addrHash, codeHash)
	}

	return fdb.cachingDB.ContractCode(addrHash, codeHash)
}

// ContractCodeSize implements Database
func (fdb *ForkingDB) ContractCodeSize(addrHash common.Hash, codeHash common.Hash) (int, error) {
	if fdb.started {
		return fdb.VerkleDB.ContractCodeSize(addrHash, codeHash)
	}

	return fdb.cachingDB.ContractCodeSize(addrHash, codeHash)
}

// CopyTrie implements Database
func (fdb *ForkingDB) CopyTrie(t Trie) Trie {
	mpt := fdb.cachingDB.CopyTrie(t)
	overlay := fdb.VerkleDB.CopyTrie(t)

	if fdb.started {
		return trie.NewTransitionTree(mpt.(*trie.SecureTrie), overlay.(*trie.VerkleTrie))
	}

	return mpt
}

// OpenStorageTrie implements Database
func (fdb *ForkingDB) OpenStorageTrie(stateRoot, addrHash, root common.Hash, self Trie) (Trie, error) {
	mpt, err := fdb.cachingDB.OpenStorageTrie(stateRoot, addrHash, root, nil)
	if fdb.started && err == nil {
		// Return a "storage trie" that is an adapter between the storge MPT
		// and the unique verkle tree.
		vkt, err := fdb.VerkleDB.OpenStorageTrie(stateRoot, addrHash, fdb.translatedRoots[root], self)
		if err != nil {
			return nil, err
		}
		return trie.NewTransitionTree(mpt.(*trie.SecureTrie), vkt.(*trie.VerkleTrie)), nil
	}

	return mpt, err
}

// OpenTrie implements Database
func (fdb *ForkingDB) OpenTrie(root common.Hash) (Trie, error) {
	mpt, err := fdb.cachingDB.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	if fdb.started {
		vkt, err := fdb.VerkleDB.OpenTrie(fdb.translatedRoots[root])
		if err != nil {
			return nil, err
		}
		return trie.NewTransitionTree(mpt.(*trie.SecureTrie), vkt.(*trie.VerkleTrie)), nil
	}

	return mpt, nil
}

// TrieDB implements Database
func (fdb *ForkingDB) TrieDB() *trie.Database {
	if fdb.started {
		return fdb.VerkleDB.TrieDB()
	}

	return fdb.cachingDB.TrieDB()
}

// DiskDB retrieves the low level trie database used for data storage.
func (fdb *ForkingDB) DiskDB() ethdb.KeyValueStore {
	if fdb.started {
		return fdb.VerkleDB.DiskDB()
	}

	return fdb.cachingDB.DiskDB()
}

func (fdg *ForkingDB) InTransition() bool {
	return fdg.started && !fdg.ended
}

// Fork implements the fork
func (fdb *ForkingDB) StartTransition(originalRoot, translatedRoot common.Hash) {
	fmt.Println(`
	__________.__                       .__                .__                   __       .__                               .__          ____         
	\__    ___|  |__   ____        ____ |  |   ____ ______ |  |__ _____    _____/  |_     |  |__ _____    ______    __  _  _|__| ____   / ___\ ______
	  |    |  |  |  \_/ __ \     _/ __ \|  | _/ __ \\____ \|  |  \\__  \  /    \   __\    |  |  \\__  \  /  ___/    \ \/ \/ |  |/    \ / /_/  /  ___/
	  |    |  |   Y  \  ___/     \  ___/|  |_\  ___/|  |_> |   Y  \/ __ \|   |  |  |      |   Y  \/ __ \_\___ \      \     /|  |   |  \\___  /\___ \
	  |____|  |___|  /\___  >     \___  |____/\___  |   __/|___|  (____  |___|  |__|      |___|  (____  /____  >      \/\_/ |__|___|  /_____//____  >
				   \/     \/          \/          \/|__|        \/     \/     \/               \/     \/     \/                     \/            \/`)
	fdb.started = true
	fdb.translatedRoots = map[common.Hash]common.Hash{originalRoot: translatedRoot}
}

func (fdb *ForkingDB) EndTransition() {
	fmt.Println(`
	__________.__                       .__                .__                   __       .__                       .__                    .___         .___
	\__    ___|  |__   ____        ____ |  |   ____ ______ |  |__ _____    _____/  |_     |  |__ _____    ______    |  | _____    ____   __| _/____   __| _/
	  |    |  |  |  \_/ __ \     _/ __ \|  | _/ __ \\____ \|  |  \\__  \  /    \   __\    |  |  \\__  \  /  ___/    |  | \__  \  /    \ / __ _/ __ \ / __ |
	  |    |  |   Y  \  ___/     \  ___/|  |_\  ___/|  |_> |   Y  \/ __ \|   |  |  |      |   Y  \/ __ \_\___ \     |  |__/ __ \|   |  / /_/ \  ___// /_/ |
	  |____|  |___|  /\___  >     \___  |____/\___  |   __/|___|  (____  |___|  |__|      |___|  (____  /____  >    |____(____  |___|  \____ |\___  \____ |
				   \/     \/          \/          \/|__|        \/     \/     \/               \/     \/     \/               \/     \/     \/    \/     \/  `)
	fdb.ended = true
}

func (fdb *ForkingDB) AddTranslation(orig, trans common.Hash) {
	// TODO make this persistent
	fdb.translatedRoots[orig] = trans
}

type cachingDB struct {
	db            *trie.Database
	disk          ethdb.KeyValueStore
	codeSizeCache *lru.Cache
	codeCache     *fastcache.Cache
}

// OpenTrie opens the main account trie at a specific root hash.
func (db *cachingDB) OpenTrie(root common.Hash) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StateTrieID(root), db.db)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// OpenStorageTrie opens the storage trie of an account.
func (db *cachingDB) OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash, _ Trie) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StorageTrieID(stateRoot, addrHash, root), db.db)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// CopyTrie returns an independent copy of the given trie.
func (db *cachingDB) CopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.StateTrie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

// ContractCode retrieves a particular contract's code.
func (db *cachingDB) ContractCode(addrHash, codeHash common.Hash) ([]byte, error) {
	if code := db.codeCache.Get(nil, codeHash.Bytes()); len(code) > 0 {
		return code, nil
	}
	code := rawdb.ReadCode(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Set(codeHash.Bytes(), code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeWithPrefix retrieves a particular contract's code. If the
// code can't be found in the cache, then check the existence with **new**
// db scheme.
func (db *cachingDB) ContractCodeWithPrefix(addrHash, codeHash common.Hash) ([]byte, error) {
	if code := db.codeCache.Get(nil, codeHash.Bytes()); len(code) > 0 {
		return code, nil
	}
	code := rawdb.ReadCodeWithPrefix(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Set(codeHash.Bytes(), code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeSize retrieves a particular contracts code's size.
func (db *cachingDB) ContractCodeSize(addrHash, codeHash common.Hash) (int, error) {
	if cached, ok := db.codeSizeCache.Get(codeHash); ok {
		return cached.(int), nil
	}
	code, err := db.ContractCode(addrHash, codeHash)
	return len(code), err
}

// DiskDB returns the underlying key-value disk database.
func (db *cachingDB) DiskDB() ethdb.KeyValueStore {
	return db.disk
}

// TrieDB retrieves any intermediate trie-node caching layer.
func (db *cachingDB) TrieDB() *trie.Database {
	return db.db
}

// VerkleDB implements state.Database for a verkle tree
type VerkleDB struct {
	db            *trie.Database
	diskdb        ethdb.KeyValueStore
	codeSizeCache *lru.Cache
	codeCache     *fastcache.Cache

	// Caches all the points that correspond to an address,
	// so they are not recalculated.
	addrToPoint *utils.PointCache
}

func (db *VerkleDB) GetTreeKeyHeader(addr []byte) *verkle.Point {
	return db.addrToPoint.GetTreeKeyHeader(addr)
}

// OpenTrie opens the main account trie.
func (db *VerkleDB) OpenTrie(root common.Hash) (Trie, error) {
	if root == (common.Hash{}) || root == emptyRoot {
		return trie.NewVerkleTrie(verkle.New(), db.db, db.addrToPoint), nil
	}
	payload, err := db.DiskDB().Get(root[:])
	if err != nil {
		return nil, err
	}

	r, err := verkle.ParseNode(payload, 0, root[:])
	if err != nil {
		panic(err)
	}
	return trie.NewVerkleTrie(r, db.db, db.addrToPoint), err
}

// OpenStorageTrie opens the storage trie of an account.
func (db *VerkleDB) OpenStorageTrie(stateRoot, addrHash, root common.Hash, self Trie) (Trie, error) {
	return self, nil
}

// CopyTrie returns an independent copy of the given trie.
func (db *VerkleDB) CopyTrie(tr Trie) Trie {
	t, ok := tr.(*trie.VerkleTrie)
	if ok {
		return t.Copy(db.db)
	}

	panic("invalid tree type != VerkleTrie")
}

// ContractCode retrieves a particular contract's code.
func (db *VerkleDB) ContractCode(addrHash, codeHash common.Hash) ([]byte, error) {
	if code := db.codeCache.Get(nil, codeHash.Bytes()); len(code) > 0 {
		return code, nil
	}
	code := rawdb.ReadCode(db.DiskDB(), codeHash)
	if len(code) > 0 {
		db.codeCache.Set(codeHash.Bytes(), code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeSize retrieves a particular contracts code's size.
func (db *VerkleDB) ContractCodeSize(addrHash, codeHash common.Hash) (int, error) {
	if code := db.codeCache.Get(nil, codeHash.Bytes()); len(code) > 0 {
		return len(code), nil
	}
	code := rawdb.ReadCode(db.DiskDB(), codeHash)
	if len(code) > 0 {
		db.codeCache.Set(codeHash.Bytes(), code)
		db.codeSizeCache.Add(codeHash, len(code))
		return len(code), nil
	}
	return 0, nil
}

// DiskDB retrieves the low level trie database used for data storage.
func (db *VerkleDB) DiskDB() ethdb.KeyValueStore {
	return db.diskdb
}

// TrieDB retrieves the low level trie database used for data storage.
func (db *VerkleDB) TrieDB() *trie.Database {
	return db.db
}
