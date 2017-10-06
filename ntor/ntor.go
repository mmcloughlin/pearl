// Package ntor implements the ntor handshake.
package ntor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/mmcloughlin/pearl/torkeys"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1073-L1088
//
//	   In this section, define:
//	      H(x,t) as HMAC_SHA256 with message x and key t.
//	      H_LENGTH  = 32.
//	      ID_LENGTH = 20.
//	      G_LENGTH  = 32
//	      PROTOID   = "ntor-curve25519-sha256-1"
//	      t_mac     = PROTOID | ":mac"
//	      t_key     = PROTOID | ":key_extract"
//	      t_verify  = PROTOID | ":verify"
//	      MULT(a,b) = the multiplication of the curve25519 point 'a' by the
//	                  scalar 'b'.
//	      G         = The preferred base point for curve25519 ([9])
//	      KEYGEN()  = The curve25519 key generation algorithm, returning
//	                  a private/public keypair.
//	      m_expand  = PROTOID | ":key_expand"
//	      KEYID(A)  = A
//
const (
	ntorProtoID = "ntor-curve25519-sha256-1"
	tKey        = ntorProtoID + ":key_extract"
	tMac        = ntorProtoID + ":mac"
	tVerify     = ntorProtoID + ":verify"
	mExpand     = ntorProtoID + ":key_expand"
)

// ServerHandshake assists with computing values in the server-side of
// circuit creation.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1100-L1106
//
//	   The server generates a keypair of y,Y = KEYGEN(), and uses its ntor
//	   private key 'b' to compute:
//
//	     secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
//	     KEY_SEED = H(secret_input, t_key)
//	     verify = H(secret_input, t_verify)
//	     auth_input = verify | ID | B | Y | X | PROTOID | "Server"
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/proposals/216-ntor-handshake.txt#L52-L54
//
//	  Set EXP(a,b) == curve25519(.,b,a), and g == 9 .  Let KEYGEN() do the
//	  appropriate manipulations when generating the secret key (clearing the
//	  low bits, twiddling the high bits).
//
type ServerHandshake struct {
	ClientPK          []byte
	ServerKeyPair     *torkeys.Curve25519KeyPair
	ServerNTORKey     *torkeys.Curve25519KeyPair
	ServerFingerprint []byte
}

func (s ServerHandshake) SecretInput() []byte {
	// BUG(mbm): SecretInput may be computed multiple times

	// Reference: https://github.com/torproject/tor/blob/7505f452c865ef9ca5be35647032f93bfb392762/src/or/onion_ntor.c#L193-L205
	//
	//	  /* build secret_input */
	//	  curve25519_handshake(si, &s.seckey_y, &s.pubkey_X);
	//	  bad = safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
	//	  si += CURVE25519_OUTPUT_LEN;
	//	  curve25519_handshake(si, &keypair_bB->seckey, &s.pubkey_X);
	//	  bad |= safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
	//	  si += CURVE25519_OUTPUT_LEN;
	//
	//	  APPEND(si, my_node_id, DIGEST_LEN);
	//	  APPEND(si, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, PROTOID, PROTOID_LEN);
	//
	var buf bytes.Buffer
	var t [32]byte
	var X [32]byte
	copy(X[:], s.ClientPK)

	// EXP(X,y)
	curve25519.ScalarMult(&t, &s.ServerKeyPair.Private, &X)
	buf.Write(t[:])

	// EXP(X,b)
	curve25519.ScalarMult(&t, &s.ServerNTORKey.Private, &X)
	buf.Write(t[:])

	// ID
	buf.Write(s.ServerFingerprint)

	// B
	buf.Write(s.ServerNTORKey.Public[:])

	// X
	buf.Write(X[:])

	// Y
	buf.Write(s.ServerKeyPair.Public[:])

	// PROTOID
	buf.Write([]byte(ntorProtoID))

	return buf.Bytes()
}

func (s ServerHandshake) KeySeed() []byte {
	return ntorHMAC(s.SecretInput(), tKey)
}

func (s ServerHandshake) Verify() []byte {
	return ntorHMAC(s.SecretInput(), tVerify)
}

func (s ServerHandshake) AuthInput() []byte {
	// Reference: https://github.com/torproject/tor/blob/7505f452c865ef9ca5be35647032f93bfb392762/src/or/onion_ntor.c#L211-L218
	//
	//	  /* Compute auth_input */
	//	  APPEND(ai, s.verify, DIGEST256_LEN);
	//	  APPEND(ai, my_node_id, DIGEST_LEN);
	//	  APPEND(ai, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, PROTOID, PROTOID_LEN);
	//	  APPEND(ai, SERVER_STR, SERVER_STR_LEN);
	//
	var buf bytes.Buffer

	// verify
	buf.Write(s.Verify())

	// ID
	buf.Write(s.ServerFingerprint)

	// B
	buf.Write(s.ServerNTORKey.Public[:])

	// Y
	buf.Write(s.ServerKeyPair.Public[:])

	// X
	buf.Write(s.ClientPK)

	// PROTOID | "Server"
	buf.Write([]byte(ntorProtoID + "Server"))

	return buf.Bytes()
}

func (s ServerHandshake) Auth() []byte {
	return ntorHMAC(s.AuthInput(), tMac)
}

func ntorHMAC(x []byte, k string) []byte {
	h := hmac.New(sha256.New, []byte(k))
	h.Write(x)
	return h.Sum(nil)
}

// KDF returns the key derivation function according to HKDF in RFC5869.
func (s ServerHandshake) KDF() io.Reader {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1193-L1214
	//
	//	5.2.2. KDF-RFC5869
	//
	//	   For newer KDF needs, Tor uses the key derivation function HKDF from
	//	   RFC5869, instantiated with SHA256.  (This is due to a construction
	//	   from Krawczyk.)  The generated key material is:
	//
	//	       K = K_1 | K_2 | K_3 | ...
	//
	//	       Where H(x,t) is HMAC_SHA256 with value x and key t
	//	         and K_1     = H(m_expand | INT8(1) , KEY_SEED )
	//	         and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
	//	         and m_expand is an arbitrarily chosen value,
	//	         and INT8(i) is a octet with the value "i".
	//
	//	   In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
	//	   salt == t_key, and IKM == secret_input.
	//
	//	   When used in the ntor handshake, the first HASH_LEN bytes form the
	//	   forward digest Df; the next HASH_LEN form the backward digest Db; the
	//	   next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
	//	   DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
	//	   hidden service protocol.  Excess bytes from K are discarded.
	//
	return hkdf.New(sha256.New, s.SecretInput(), []byte(tKey), []byte(mExpand))
}
