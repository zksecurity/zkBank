package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestProveAndVerify(t *testing.T) {
	circuit := Circuit{
		// fixed
		AliceBalance: aliceBalance,
		// fixed
		BobBalance: bobBalance,
		// given by the user
		NewBobBalance: 500,
		// given by the user
		NewAliceBalance: 0,
		// private
		Transfer: 500,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error occured ", err)
	}

	// create a proof
	proof, err := groth16.Prove(
		oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)),
	)
	if err != nil {
		t.Fatal(err)
	}

	// serialize proof verify
	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	proofHex := hex.EncodeToString(buf.Bytes())
	err = VerifyProof("500", proofHex)
	if err != nil {
		t.Fatal(err)
	}
}
