package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

type account struct{}

func (account) SubBalance(amount *big.Int)                          {}
func (account) AddBalance(amount *big.Int)                          {}
func (account) SetAddress(common.Address)                           {}
func (account) Value() *big.Int                                     { return nil }
func (account) SetBalance(*big.Int)                                 {}
func (account) SetNonce(uint64)                                     {}
func (account) Balance() *big.Int                                   { return nil }
func (account) Address() common.Address                             { return common.Address{} }
func (account) SetCode(common.Hash, []byte)                         {}
func (account) ForEachStorage(cb func(key, value common.Hash) bool) {}

func TestStaticCall(t *testing.T) {
	var from [20]byte
	from[0] = 1
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	evm := vm.NewEVM(vm.BlockContext{}, vm.TxContext{}, statedb, &params.ChainConfig{}, vm.Config{})
	caller := vm.NewContract(&account{}, &account{}, big.NewInt(0), 100000)

	var dest [20]byte
	gas := uint64(100000000)
	input := []byte{0, 1, 2, 3}
	evm.StaticCall(caller, common.BytesToAddress(dest[:]), input, gas)
}
