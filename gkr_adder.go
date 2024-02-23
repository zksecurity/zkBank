package zksec_gkr

import (
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	hashMimc "github.com/consensys/gnark-crypto/hash"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
	hashMimcCircuit "github.com/consensys/gnark/std/hash/mimc"
)

func init() {
	InitializeBalanceGKR()
}

// This computes X + Y = Z using GKR
type BalanceGKR struct {
	X []frontend.Variable
	Y []frontend.Variable
	Z []frontend.Variable

	counter int

	api frontend.API
}

func NewBalanceGKR(api frontend.API, bN int) *BalanceGKR {
	return &BalanceGKR{
		X: make([]frontend.Variable, 1<<bN),
		Y: make([]frontend.Variable, 1<<bN),
		Z: make([]frontend.Variable, 1<<bN),

		counter: 0,
		api:     api,
	}
}

func (m *BalanceGKR) VerifyGKR(challenges ...frontend.Variable) error {
	if m.counter == 0 {
		panic("are you even using the app bro?")
	}

	for i := m.counter; i < len(m.X); i++ {
		m.X[i] = 0
		m.Y[i] = 0
		m.Z[i] = 0
	}

	_gkr := gkr.NewApi()
	x, err := _gkr.Import(m.X)
	if err != nil {
		return err
	}
	y, err := _gkr.Import(m.Y)
	if err != nil {
		return err
	}

	z := _gkr.Add(x, y)

	solution, err := _gkr.Solve(m.api)
	if err != nil {
		return err
	}

	Z_gkr := solution.Export(z)
	err = solution.Verify("mimc", challenges...)
	if err != nil {
		return err
	}

	for i := 0; i < m.counter; i++ {
		m.api.AssertIsEqual(m.Z[i], Z_gkr[i])
	}

	return nil
}

func (m *BalanceGKR) AddCircuit(il, ir frontend.Variable) frontend.Variable {
	m.X[m.counter] = il
	m.Y[m.counter] = ir

	results, err := m.api.Compiler().NewHint(TransferHint, 1, il, ir)
	if err != nil {
		panic("failed to run hint, err: " + err.Error())
	}
	m.Z[m.counter] = results[0]

	m.counter++

	return results[0]
}

func TransferHint(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	lhs := new(fr.Element).SetBigInt(inputs[0])
	rhs := new(fr.Element).SetBigInt(inputs[1])

	var res fr.Element
	res.Add(rhs, lhs)

	bytes := res.Bytes()
	results[0].SetBytes(bytes[:])

	return nil
}

func InitializeBalanceGKR() {
	bn254r1cs.RegisterHashBuilder("mimc", func() hash.Hash {
		return hashMimc.MIMC_BN254.New()
	})
	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := hashMimcCircuit.NewMiMC(api)
		return &m, err
	})
}
