package trie

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestReStackTrieLeafInsert(t *testing.T) {
	root := NewReStackTrie()
	root.insert(common.FromHex("01020304"), common.FromHex("00001"))
	root.insert(common.FromHex("01020305"), common.FromHex("00002"))
	root.insert(common.FromHex("0102030f"), common.FromHex("00003"))
	root.insert(common.FromHex("0103030f"), common.FromHex("00004"))
	root.insert(common.FromHex("0203030f"), common.FromHex("00005"))
	root.insert(common.FromHex("0204030f"), common.FromHex("00006"))
}

// TODO insert in a key parce que pour le moment je ne fais qu'inserer dans
// des ext et donc je n'ai pas teste les cles.
