package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

//
// Account Balances
//

const (
	aliceBalance = 500
	bobBalance   = 0
)

//
// Setup
//

var pk groth16.ProvingKey
var vk groth16.VerifyingKey

func init() {
	// deserialize vk
	vkHex := "8467312eb865cac8d12ab64d7c7462ecbd5f1fb216ca81d4339855f1124c030bd1ddc9d87fd7b3eaa13bac7fbf488f15050d2c59cf3946bc480060607b9ad61cefe462f13073db796413ae359626f73a24327c0dcb5b495aecb29a7fb4c84b130f1f2f346f1ccb158de03c8697749986f12e9349e5b3dfa4ebd925c3d802a222a0496b1cbbc6921a5b76452d7b06ef3b4923aee55a5802713e4f47170562c751169b084ba470117df85a9706ebadd5dcb174e1d56c36343188ef871fdb8d55638683f92b67964dffa64f84b990b0e5f5755a7ed3ebce2a386d09ca15c2683223d2e737efaeb906c0d5424170286f6b2b8f4b9c0827678a492955e42d49276db7178b814f1de3c748cb24cbac562a1e0ec250c5d99ed7d45c22a4a302ffa6c30100000004d256cb4de2a676679ff52e0d6e8271f8cd06998ed2b31977dfdb899051e2487ea54b18d47c83415c71c68297955a565ff6f3506e79cb2e2cb49dfaec376c3ec7a3b33f90a349a5e89d612463a87f91ce2d80cb9fe6945dbcb6ffad620e1cd82288030a843cffb79f2bc292607e34f9fb982430555f4abbf0f2a51070f29375bd00000000d9a19980eb3e20ffe553ac0933bd29b467f3052f11ff7f46e64a5252e3fb27ed258f58ca0dc9173d1e6468e3006fb4be84195eaf2f6e431488747fb9c601c950ac7fe33ec763786b9b4d67e5df97b7e4ca4751771aa0b263fc9c2f3b3888a279255e59f565edfbc603077757ae26b0b9bd0264c8797bf699949bf859fcc7069d"
	vkBytes, _ := hex.DecodeString(vkHex)
	vk = groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(bytes.NewReader(vkBytes))

	// deserialize pk from disk
	pkBytes, err := os.ReadFile("./pk.bin")
	if err != nil {
		panic(err)
	}
	pk = groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewReader(pkBytes))
	if err != nil {
		panic(err)
	}
}

//
// Circuit to ensure that a transfer is legit
//

type Circuit struct {
	// note: Alice only has 500 tokens in her account
	AliceBalance frontend.Variable `gnark:",public"`
	// note: Bob has 0 tokens in his account
	BobBalance      frontend.Variable `gnark:",public"`
	NewBobBalance   frontend.Variable `gnark:",public"`
	NewAliceBalance frontend.Variable
	Transfer        frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	// init
	gkrBalance := NewBalanceGKR(api, 1)

	// transfer is legit?
	api.AssertIsLessOrEqual(circuit.Transfer, circuit.AliceBalance)

	// new balance for Alice
	negated := api.Neg(circuit.Transfer)
	newAliceBalance := gkrBalance.AddCircuit(circuit.AliceBalance, negated)
	api.AssertIsEqual(newAliceBalance, circuit.NewAliceBalance)

	// new balance for Bob
	newBobBalance := gkrBalance.AddCircuit(circuit.BobBalance, circuit.Transfer)
	api.AssertIsEqual(newBobBalance, circuit.NewBobBalance)

	// GKR verifier
	err := gkrBalance.VerifyGKR(circuit.AliceBalance, circuit.BobBalance)
	if err != nil {
		panic(err)
	}
	return nil
}

// this is the function we run on the server side
func VerifyProof(newBobBalanceStr string, proofHex string) error {
	// deserialize proof
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return err
	}
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return err
	}

	// parse newBobBalance
	var newBobBalance big.Int
	_, success := newBobBalance.SetString(newBobBalanceStr, 10)
	if !success {
		return fmt.Errorf("failed to parse newBobBalance as decimal string")
	}
	var fieldSize big.Int
	fieldSize.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	if newBobBalance.Cmp(&fieldSize) >= 0 {
		return fmt.Errorf("newBobBalance is greater than field size")
	}

	// ensure that it's greater than 100,000
	requiredThreshold := big.NewInt(100000)
	if newBobBalance.Cmp(requiredThreshold) < 0 {
		return fmt.Errorf("newBobBalance is less than 100,000")
	}

	// set witness with fixed public inputs
	circuit := Circuit{
		// fixed
		AliceBalance: aliceBalance,
		// fixed
		BobBalance: bobBalance,
		// given by user
		NewBobBalance: newBobBalance,
		// not part of public input, ignore
		NewAliceBalance: 0,
		Transfer:        0,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return err
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return err
	}

	return nil
}
