// Package ntor implements the ntor handshake.
package ntor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"

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

// Public contains values both sides have in the handshake.
type Public struct {
	KX [32]byte
	KY [32]byte
	KB [32]byte
	ID []byte
}

func (p Public) Shared() Public { return p }

// Handshake is a common interface for either side of the handshake.
type Handshake interface {
	Shared() Public
	SecretInput() []byte
}

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
type ServerHandshake struct {
	Public
	Ky [32]byte
	Kb [32]byte
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
	buf.Write(exp(s.KX, s.Ky))
	buf.Write(exp(s.KX, s.Kb))
	buf.Write(s.ID)
	buf.Write(s.KB[:])
	buf.Write(s.KX[:])
	buf.Write(s.KY[:])
	buf.Write([]byte(ntorProtoID))
	return buf.Bytes()
}

type ClientHandshake struct {
	Public
	Kx [32]byte
}

func (c ClientHandshake) SecretInput() []byte {
	// Reference: https://github.com/torproject/tor/blob/7505f452c865ef9ca5be35647032f93bfb392762/src/or/onion_ntor.c#L276-L288
	//
	//	  /* Compute secret_input */
	//	  curve25519_handshake(si, &handshake_state->seckey_x, &s.pubkey_Y);
	//	  bad = safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
	//	  si += CURVE25519_OUTPUT_LEN;
	//	  curve25519_handshake(si, &handshake_state->seckey_x,
	//	                       &handshake_state->pubkey_B);
	//	  bad |= (safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN) << 1);
	//	  si += CURVE25519_OUTPUT_LEN;
	//	  APPEND(si, handshake_state->router_id, DIGEST_LEN);
	//	  APPEND(si, handshake_state->pubkey_B.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, handshake_state->pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, PROTOID, PROTOID_LEN);
	//
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1112-L1117
	//
	//	   The client then checks Y is in G^* [see NOTE below], and computes
	//
	//	     secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
	//	     KEY_SEED = H(secret_input, t_key)
	//	     verify = H(secret_input, t_verify)
	//	     auth_input = verify | ID | B | Y | X | PROTOID | "Server"
	//
	var buf bytes.Buffer
	buf.Write(exp(c.KY, c.Kx))
	buf.Write(exp(c.KB, c.Kx))
	buf.Write(c.ID)
	buf.Write(c.KB[:])
	buf.Write(c.KX[:])
	buf.Write(c.KY[:])
	buf.Write([]byte(ntorProtoID))
	return buf.Bytes()
}

func KeySeed(h Handshake) []byte {
	return ntorHMAC(h.SecretInput(), tKey)
}

func Verify(h Handshake) []byte {
	return ntorHMAC(h.SecretInput(), tVerify)
}

func AuthInput(h Handshake) []byte {
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
	s := h.Shared()
	buf.Write(Verify(h))
	buf.Write(s.ID)
	buf.Write(s.KB[:])
	buf.Write(s.KY[:])
	buf.Write(s.KX[:])
	buf.Write([]byte(ntorProtoID + "Server"))
	return buf.Bytes()
}

func Auth(h Handshake) []byte {
	return ntorHMAC(AuthInput(h), tMac)
}

// KDF returns the key derivation function according to HKDF in RFC5869.
func KDF(h Handshake) io.Reader {
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
	return hkdf.New(sha256.New, h.SecretInput(), []byte(tKey), []byte(mExpand))
}

// exp is a convenience wrapper around curve25519 multiplication so our code can
// match the EXP() function in the spec.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/proposals/216-ntor-handshake.txt#L52-L54
//
//	  Set EXP(a,b) == curve25519(.,b,a), and g == 9 .  Let KEYGEN() do the
//	  appropriate manipulations when generating the secret key (clearing the
//	  low bits, twiddling the high bits).
//
func exp(a, b [32]byte) []byte {
	var t [32]byte
	curve25519.ScalarMult(&t, &b, &a)
	return t[:]
}

// ntorHMAC performs a HMAC-SHA256 with the given key.
func ntorHMAC(x []byte, k string) []byte {
	h := hmac.New(sha256.New, []byte(k))
	h.Write(x)
	return h.Sum(nil)
}
