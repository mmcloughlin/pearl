// Package debug contains debugging helpers.
package debug

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mmcloughlin/pearl/torcrypto"
)

func DumpBytes(name string, data []byte) error {
	fmt.Print(hex.Dump(data))
	return ioutil.WriteFile(filename(name), data, 0640)
}

func DumpByteArray(name string, data []byte) error {
	f, err := os.Create(filename(name))
	if err != nil {
		return err
	}

	fmt.Fprint(f, GoStringByteArray(data))

	return f.Close()
}

func GoStringByteArray(data []byte) string {
	var buf bytes.Buffer
	fmt.Fprint(&buf, "[]byte{")
	for i, b := range data {
		if i%16 == 0 {
			fmt.Fprint(&buf, "\n\t")
		}
		fmt.Fprintf(&buf, "0x%02x, ", b)
	}
	fmt.Fprint(&buf, "\n}")
	return string(buf.Bytes())
}

func GoStringRSAPrivateKey(k *rsa.PrivateKey) string {
	pem := torcrypto.MarshalRSAPrivateKeyPKCS1PEM(k)
	return fmt.Sprintf("torcrypto.MustRSAPrivateKey(torcrypto.ParseRSAPrivateKeyPKCS1PEM([]byte(%#v)))", string(pem))
}

func GoStringRSAPublicKey(k *rsa.PublicKey) string {
	pem, err := torcrypto.MarshalRSAPublicKeyPKCS1PEM(k)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("torcrypto.MustRSAPublicKey(torcrypto.ParseRSAPublicKeyPKCS1PEM([]byte(%#v)))", string(pem))
}

func filename(name string) string {
	return filepath.Join("output", name)
}
