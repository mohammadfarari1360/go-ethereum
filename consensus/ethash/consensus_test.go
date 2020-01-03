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

package ethash

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type diffTest struct {
	ParentTimestamp    uint64
	ParentDifficulty   *big.Int
	CurrentTimestamp   uint64
	CurrentBlocknumber *big.Int
	CurrentDifficulty  *big.Int
}

func (d *diffTest) UnmarshalJSON(b []byte) (err error) {
	var ext struct {
		ParentTimestamp    string
		ParentDifficulty   string
		CurrentTimestamp   string
		CurrentBlocknumber string
		CurrentDifficulty  string
	}
	if err := json.Unmarshal(b, &ext); err != nil {
		return err
	}

	d.ParentTimestamp = math.MustParseUint64(ext.ParentTimestamp)
	d.ParentDifficulty = math.MustParseBig256(ext.ParentDifficulty)
	d.CurrentTimestamp = math.MustParseUint64(ext.CurrentTimestamp)
	d.CurrentBlocknumber = math.MustParseBig256(ext.CurrentBlocknumber)
	d.CurrentDifficulty = math.MustParseBig256(ext.CurrentDifficulty)

	return nil
}

func TestCalcDifficulty(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "tests", "testdata", "BasicTests", "difficulty.json"))
	if err != nil {
		t.Skip(err)
	}
	defer file.Close()

	tests := make(map[string]diffTest)
	err = json.NewDecoder(file).Decode(&tests)
	if err != nil {
		t.Fatal(err)
	}

	config := &params.ChainConfig{HomesteadBlock: big.NewInt(1150000)}

	for name, test := range tests {
		number := new(big.Int).Sub(test.CurrentBlocknumber, big.NewInt(1))
		diff := CalcDifficulty(config, test.CurrentTimestamp, &types.Header{
			Number:     number,
			Time:       test.ParentTimestamp,
			Difficulty: test.ParentDifficulty,
		})
		if diff.Cmp(test.CurrentDifficulty) != 0 {
			t.Error(name, "failed. Expected", test.CurrentDifficulty, "and calculated", diff)
		}
	}
}

type mockChainReader struct {
	header  *types.Header
	headers []types.Header
}

// Config retrieves the blockchain's chain configuration.
func (m *mockChainReader) Config() *params.ChainConfig {
	return &params.ChainConfig{
		DAOForkBlock:   big.NewInt(15),
		ByzantiumBlock: big.NewInt(42),
	}
}

// CurrentHeader retrieves the current header from the local chain.
func (m *mockChainReader) CurrentHeader() *types.Header {
	return nil
}

// GetHeader retrieves a block header from the database by hash and number.
func (m *mockChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if m.header != nil {
		if m.header.Number.Uint64() == number {
			return m.header
		}
	} else {
		if m.headers != nil {
			for _, h := range m.headers {
				if h.Number.Uint64() == number {
					return &h
				}
			}
		}
	}

	return nil
}

// GetHeaderByNumber retrieves a block header from the database by number.
func (m *mockChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return nil
}

// GetHeaderByHash retrieves a block header from the database by its hash.
func (m *mockChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return nil
}

// GetBlock retrieves a block from the database by hash and number.
func (m *mockChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return nil
}

func TestAuthor(t *testing.T) {
	ethash := &Ethash{}
	coinbase := common.BytesToAddress(common.FromHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	header := &types.Header{
		Number:   big.NewInt(38),
		Coinbase: coinbase,
	}
	addr, err := ethash.Author(header)
	if err != nil {
		t.Fatalf("Getting the author of a block from its header should return no error, got %v", err)
	}
	if addr != coinbase {
		t.Fatalf("Author is different from the coinbase: %v != %v", coinbase.Hex(), addr.Hex())
	}
}

func TestVerifyHeader(t *testing.T) {
	tests := []struct {
		number   int64
		parent   int64
		name     string
		err      error
		gasLimit uint64
		gasUsed  uint64
		config   Config
	}{
		{
			number:   38,
			parent:   37,
			name:     "FullFake",
			err:      nil,
			gasUsed:  params.MinGasLimit / 2,
			gasLimit: params.MinGasLimit,
			config:   Config{PowMode: ModeFullFake},
		},
		{
			number:   38,
			parent:   36,
			name:     "PresenceOfParentBlock",
			err:      consensus.ErrUnknownAncestor,
			gasUsed:  params.MinGasLimit / 2,
			gasLimit: params.MinGasLimit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ethash := &Ethash{config: test.config}
			header := &types.Header{
				Number:     big.NewInt(test.number),
				Time:       uint64(time.Now().Unix()),
				Difficulty: big.NewInt(131072),
				GasLimit:   test.gasLimit,
				GasUsed:    test.gasUsed,
			}
			chain := &mockChainReader{
				header: &types.Header{
					Number:     big.NewInt(test.parent),
					Time:       uint64(time.Now().Unix() - 1),
					Difficulty: big.NewInt(1),
				},
			}

			err := ethash.VerifyHeader(chain, header, false)
			if err != test.err {
				t.Fatalf("invalild error: got %v, expected %v", err, test.err)
			}
		})
	}
}

func TestVerifyHeaderBlockPresentShortCircuit(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number: big.NewInt(38),
	}
	if ethash.VerifyHeader(&mockChainReader{header: header}, header, false) != nil {
		t.Fatal("Should not try to recover a block that is already known")
	}
}

func TestVerifyExtraDataSize(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number: big.NewInt(38),
		Time:   uint64(time.Now().Unix()),
		Extra:  make([]byte, params.MaximumExtraDataSize+1),
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number: big.NewInt(37),
			Time:   uint64(time.Now().Unix() - 1),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err == nil || err.Error() != "extra-data too long: 33 > 32" {
		t.Fatalf("Should refuse a block with too much extra data, err=: %v", err)
	}
}

func TestVerifyFutureBlock(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number: big.NewInt(38),
		Time:   uint64(time.Now().Add(24 * time.Hour).Unix()),
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number: big.NewInt(37),
			Time:   uint64(time.Now().Unix()),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err != consensus.ErrFutureBlock {
		t.Fatalf("Expected verify to flag the block as too far in the future, got: %v", err)
	}
}

func TestVerifyBlockOlderThanParent(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number: big.NewInt(38),
		Time:   uint64(time.Now().Unix() - 1),
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number: big.NewInt(37),
			Time:   uint64(time.Now().Unix()),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err != errOlderBlockTime {
		t.Fatalf("Expected verify to flag the block as too far in the future, got: %v", err)
	}
}

func TestVerifyCheckInvalidDifficulty(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number:     big.NewInt(38),
		Time:       uint64(time.Now().Unix()),
		Difficulty: big.NewInt(1),
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number:     big.NewInt(37),
			Time:       uint64(time.Now().Unix() - 1),
			Difficulty: big.NewInt(1),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err == nil || err.Error() != "invalid difficulty: have 1, want 131072" {
		t.Fatalf("Expected an invalid difficulty, got: %v", err)
	}
}

func TestVerifyCheckGasLimit(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number:     big.NewInt(38),
		Time:       uint64(time.Now().Unix()),
		Difficulty: big.NewInt(131072),
		GasLimit:   uint64(0x7fffffffffffffff) + 1,
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number:     big.NewInt(37),
			Time:       uint64(time.Now().Unix() - 1),
			Difficulty: big.NewInt(1),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err == nil || err.Error() != fmt.Sprintf("invalid gasLimit: have %d, max %d", uint64(0x7fffffffffffffff)+1, uint64(0x7fffffffffffffff)) {
		t.Fatalf("Expected an invalid gas usage, got: %v", err)
	}
}

func TestVerifyCheckGasUsed(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number:     big.NewInt(38),
		Time:       uint64(time.Now().Unix()),
		Difficulty: big.NewInt(131072),
		GasLimit:   33,
		GasUsed:    38,
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number:     big.NewInt(37),
			Time:       uint64(time.Now().Unix() - 1),
			Difficulty: big.NewInt(1),
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err == nil || err.Error() != fmt.Sprintf("invalid gasUsed: have %d, gasLimit %d", 38, 33) {
		t.Fatalf("Expected an invalid gas usage, got: %v", err)
	}
}

func TestVerifyCheckGasLimitBound(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number:     big.NewInt(38),
		Time:       uint64(time.Now().Unix()),
		Difficulty: big.NewInt(131072),
		GasLimit:   38,
		GasUsed:    33,
	}
	chain := &mockChainReader{
		header: &types.Header{
			Number:     big.NewInt(37),
			Time:       uint64(time.Now().Unix() - 1),
			Difficulty: big.NewInt(1),
			GasLimit:   36,
		},
	}
	err := ethash.VerifyHeader(chain, header, false)
	if err == nil || err.Error() != fmt.Sprintf("invalid gas limit: have %d, want %d += 0", header.GasLimit, chain.header.GasLimit) {
		t.Fatalf("Expected an invalid gas usage, got: %v", err)
	}
}

func TestByzantiumCalcDiff(t *testing.T) {
	ethash := &Ethash{}
	header := &types.Header{
		Number:     big.NewInt(44),
		Time:       uint64(time.Now().Unix()),
		Difficulty: big.NewInt(131072),
		GasLimit:   params.MinGasLimit,
		GasUsed:    33,
	}
	parent := &types.Header{
		Number:     big.NewInt(43),
		Time:       uint64(time.Now().Unix() - 1),
		Difficulty: big.NewInt(1),
		GasLimit:   params.MinGasLimit,
	}
	chain := &mockChainReader{
		header: parent,
	}

	expected := ethash.CalcDifficulty(chain, header.Time, parent)
	fmt.Println(expected, chain.Config().IsByzantium(header.Number), chain.Config().ByzantiumBlock)
}
