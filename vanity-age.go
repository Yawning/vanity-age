package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/edwards25519"
	"github.com/danwakefield/fnmatch"
	"github.com/yawning/vanity-age/internal/bech32"
)

var pIncr = func() *edwards25519.Point {
	p := edwards25519.NewGeneratorPoint()
	return p.MultByCofactor(p)
}()

func main() {
	if len(os.Args) == 1 {
		fmt.Println(
			`no query
rules:
  *     - match anything
  ?     - match any single character
  [seq] - match any character in seq
 [!seq] - match any character not in seq
age keys are 58 characters long, excluding 'age1'`)
		return
	}

	query := "age1" + os.Args[1]

	keyChan := make(chan *age.X25519Identity)
	// startTime := time.Now()
	for i := 0; i < runtime.NumCPU(); i++ {
		go generate(query, keyChan)
	}

	key := <-keyChan
	// elapsed := time.Since(startTime)

	// fmt.Println("# search took: ", elapsed)
	fmt.Println("# created:", time.Now().Format(time.RFC3339))
	fmt.Println("# public key:", key.Recipient())
	fmt.Println(key)
}

func clampScalar(in []byte) []byte {
	b := make([]byte, 32)
	copy(b, in)

	b[0] &= 248
	b[31] &= 127
	b[31] |= 64

	return b
}

func scalarAddLE(dst, a, b *[32]byte) {
	var v [32]int
	var carry int

	for i := 0; i < 32; i++ {
		v[i] = int(a[i]) + int(b[i])
	}
	for i := 0; i < 31; i++ {
		carry = v[i] >> 8
		v[i+1] += carry
		v[i] &= 0xff
	}
	for i := 0; i < 32; i++ {
		dst[i] = byte(v[i])
	}
}

func generate(query string, keyChan chan *age.X25519Identity) {
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("entropy source faulure:" + err.Error())
		}
		sc, _ := edwards25519.NewScalar().SetBytesWithClamping(b[:])
		p := edwards25519.NewIdentityPoint().ScalarBaseMult(sc)

		scBytes := clampScalar(b[:])

	incrLoop:
		for i := uint64(0); i < math.MaxUint64-16; i = i + 8 {
			str, _ := bech32.Encode("age", p.BytesMontgomery())
			if fnmatch.Match(query, str, fnmatch.FNM_IGNORECASE) {
				// Sigh.  It would be nicer to use edwards25519.Scalar, but
				// the stupid fucking "clamping" requires us to do things
				// the hard way.
				//
				// SetBytesWithClamping has a reduction, that does not
				// occur when doing X25519.
				var scIncr [32]byte
				binary.LittleEndian.PutUint64(scIncr[0:8], i)
				scalarAddLE((*[32]byte)(scBytes), (*[32]byte)(scBytes), &scIncr)
				if !bytes.Equal(clampScalar(scBytes), scBytes) {
					// Unlikely, but this can happen.
					break incrLoop
				}

				privStr, _ := bech32.Encode("AGE-SECRET-KEY-", scBytes[:])
				privStr = strings.ToUpper(privStr)
				ident, err := age.ParseX25519Identity(privStr)
				if err != nil {
					panic("created bad priv key: " + err.Error())
				}
				if ident.Recipient().String() != str {
					// Probably impossible.
					break incrLoop
				}

				keyChan <- ident
				return
			}

			p.Add(p, pIncr)
		}
	}
}
