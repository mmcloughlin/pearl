package pearl

import (
	cryptorand "crypto/rand"
	"io"
	"math/big"
	"math/rand"
	"time"

	"github.com/mmcloughlin/openssl"
	"github.com/mmcloughlin/pearl/torkeys"
)

// TLSContext manages TLS parameters for a connection.
type TLSContext struct {
	ctx *openssl.Ctx

	IDCert   *openssl.Certificate
	LinkKey  openssl.PrivateKey
	LinkCert *openssl.Certificate
	AuthKey  openssl.PrivateKey
	AuthCert *openssl.Certificate
}

// NewTLSContext builds a TLS context for a new connection with the given
// identity key.
func NewTLSContext(idKey openssl.PrivateKey) (*TLSContext, error) {
	var err error

	tls := &TLSContext{}
	tls.ctx, err = newSSLCtx()
	if err != nil {
		return nil, err
	}

	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L225-L245
	//
	//	   In "in-protocol" (a.k.a. "the v3 handshake"), the initiator sends no
	//	   certificates, and the
	//	   responder sends a single connection certificate.  The choice of
	//	   ciphersuites must be as in a "renegotiation" handshake.  There are
	//	   additionally a set of constraints on the connection certificate,
	//	   which the initiator can use to learn that the in-protocol handshake
	//	   is in use.  Specifically, at least one of these properties must be
	//	   true of the certificate:
	//	      * The certificate is self-signed
	//	      * Some component other than "commonName" is set in the subject or
	//	        issuer DN of the certificate.
	//	      * The commonName of the subject or issuer of the certificate ends
	//	        with a suffix other than ".net".
	//	      * The certificate's public key modulus is longer than 1024 bits.
	//	   The initiator then sends a VERSIONS cell to the responder, which then
	//	   replies with a VERSIONS cell; they have then negotiated a Tor
	//	   protocol version.  Assuming that the version they negotiate is 3 or higher
	//	   (the only ones specified for use with this handshake right now), the
	//	   responder sends a CERTS cell, an AUTH_CHALLENGE cell, and a NETINFO
	//	   cell to the initiator, which may send either CERTS, AUTHENTICATE,
	//	   NETINFO if it wants to authenticate, or just NETINFO if it does not.
	//
	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1061-L1066
	//
	//	  nickname = crypto_random_hostname(8, 20, "www.", ".net");
	//	#ifdef DISABLE_V3_LINKPROTO_SERVERSIDE
	//	  nn2 = crypto_random_hostname(8, 20, "www.", ".net");
	//	#else
	//	  nn2 = crypto_random_hostname(8, 20, "www.", ".com");
	//	#endif
	//

	linkCN := randomHostname(8, 20, "www.", ".net")
	idCN := randomHostname(8, 20, "www.", ".com")

	// Generate identity certificate.
	//
	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1083-L1085
	//
	//	    /* Create self-signed certificate for identity key. */
	//	    idcert = tor_tls_create_certificate(identity, identity, nn2, nn2,
	//	                                        IDENTITY_CERT_LIFETIME);
	//
	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L67-L68
	//
	//	/** How long do identity certificates live? (sec) */
	//	#define IDENTITY_CERT_LIFETIME  (365*24*60*60)
	//

	idLifetime := time.Duration(365*24) * time.Hour

	tls.IDCert, err = generateCertificate(idCN, idKey, idLifetime)
	if err != nil {
		return nil, err
	}

	err = setIssuerAndSignCertificate(tls.IDCert, tls.IDCert, idKey)
	if err != nil {
		return nil, err
	}

	// Certificate lifetime is either set by the SSLKeyLifetime option or
	// generated to a reasonable looking value.
	//
	// BUG(mmcloughlin): SSLKeyLifetime option ignored when generating
	// certificates.
	lifetime := generateCertificateLifetime()

	// Generate link certificate.
	//
	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1080-L1082
	//
	//	    /* Create a link certificate signed by identity key. */
	//	    cert = tor_tls_create_certificate(rsa, identity, nickname, nn2,
	//	                                      key_lifetime);
	//

	// BUG(mmcloughlin): link key should be 2048 bits
	tls.LinkKey, err = torkeys.GenerateRSA()
	if err != nil {
		return nil, err
	}

	tls.LinkCert, err = generateCertificate(linkCN, tls.LinkKey, lifetime)
	if err != nil {
		return nil, err
	}

	err = setIssuerAndSignCertificate(tls.LinkCert, tls.IDCert, idKey)
	if err != nil {
		return nil, err
	}

	// Generate auth certificate.

	tls.AuthKey, err = torkeys.GenerateRSA()
	if err != nil {
		return nil, err
	}

	tls.AuthCert, err = generateCertificate(linkCN, tls.AuthKey, lifetime)
	if err != nil {
		return nil, err
	}

	err = setIssuerAndSignCertificate(tls.AuthCert, tls.IDCert, idKey)
	if err != nil {
		return nil, err
	}

	tls.ctx.UseCertificate(tls.LinkCert)
	tls.ctx.UsePrivateKey(tls.LinkKey)

	return tls, nil
}

func (t *TLSContext) Ctx() *openssl.Ctx {
	return t.ctx
}

// newSSLCtx builds a new openssl context configured with options required by
// Tor.
func newSSLCtx() (*openssl.Ctx, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1209-L1216
	//
	//	    if (flags & TOR_TLS_CTX_USE_ECDHE_P224)
	//	      nid = NID_secp224r1;
	//	    else if (flags & TOR_TLS_CTX_USE_ECDHE_P256)
	//	      nid = NID_X9_62_prime256v1;
	//	    else
	//	      nid = NID_tor_default_ecdhe_group;
	//	    /* Use P-256 for ECDHE. */
	//	    ec_key = EC_KEY_new_by_curve_name(nid);
	//
	ctx.SetEllipticCurve(openssl.Prime256v1)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1124-L1125
	//
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_NO_SSLv2);
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_NO_SSLv3);
	//
	ctx.SetOptions(openssl.NoSSLv2 | openssl.NoSSLv3)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1127-L1129
	//
	//	  /* Prefer the server's ordering of ciphers: the client's ordering has
	//	  * historically been chosen for fingerprinting resistance. */
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	//
	ctx.SetOptions(openssl.CipherServerPreference)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1131-L1145
	//
	//	  /* Disable TLS tickets if they're supported.  We never want to use them;
	//	   * using them can make our perfect forward secrecy a little worse, *and*
	//	   * create an opportunity to fingerprint us (since it's unusual to use them
	//	   * with TLS sessions turned off).
	//	   *
	//	   * In 0.2.4, clients advertise support for them though, to avoid a TLS
	//	   * distinguishability vector.  This can give us worse PFS, though, if we
	//	   * get a server that doesn't set SSL_OP_NO_TICKET.  With luck, there will
	//	   * be few such servers by the time 0.2.4 is more stable.
	//	   */
	//	#ifdef SSL_OP_NO_TICKET
	//	  if (! is_client) {
	//	    SSL_CTX_set_options(result->ctx, SSL_OP_NO_TICKET);
	//	  }
	//	#endif
	//
	ctx.SetOptions(openssl.NoTicket)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1172-L1174
	//
	//	#ifdef SSL_MODE_RELEASE_BUFFERS
	//	  SSL_CTX_set_mode(result->ctx, SSL_MODE_RELEASE_BUFFERS);
	//	#endif
	//
	ctx.SetMode(openssl.ReleaseBuffers)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1147-L1148
	//
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_SINGLE_DH_USE);
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_SINGLE_ECDH_USE);
	//
	ctx.SetOptions(openssl.SingleDHUse | openssl.SingleECDHUse)

	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L382-L384
	//
	//	   Implementations MUST NOT allow TLS session resumption -- it can
	//	   exacerbate some attacks (e.g. the "Triple Handshake" attack from
	//	   Feb 2013), and it plays havoc with forward secrecy guarantees.
	//
	ctx.SetOptions(openssl.NoSessionResumptionOrRenegotiation)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1161-L1163
	//
	//	#ifdef SSL_OP_NO_COMPRESSION
	//	  SSL_CTX_set_options(result->ctx, SSL_OP_NO_COMPRESSION);
	//	#endif
	//
	ctx.SetOptions(openssl.NoCompression)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1188
	//
	//	  SSL_CTX_set_session_cache_mode(result->ctx, SSL_SESS_CACHE_OFF);
	//
	ctx.SetSessionCacheMode(openssl.SessionCacheOff)

	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L1221-L1222
	//
	//	  SSL_CTX_set_verify(result->ctx, SSL_VERIFY_PEER,
	//	                     always_accept_verify_cb);
	//
	ctx.SetVerify(openssl.VerifyNone, nil)

	return ctx, nil
}

func generateCertificate(cn string, key openssl.PrivateKey, lifetime time.Duration) (*openssl.Certificate, error) {
	serial, err := generateCertificateSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	issued := generateCertificateIssued(now, lifetime)
	issuedDuration := issued.Sub(now)

	return openssl.NewCertificate(&openssl.CertificateInfo{
		CommonName: cn,
		Serial:     serial,
		Issued:     issuedDuration,
		Expires:    issuedDuration + lifetime,
	}, key)
}

func setIssuerAndSignCertificate(cert, issuer *openssl.Certificate, key openssl.PrivateKey) error {
	err := cert.SetIssuer(issuer)
	if err != nil {
		return err
	}

	err = cert.Sign(key, openssl.EVP_SHA256)
	if err != nil {
		return err
	}

	return nil
}

// randomHostname generates a hostname starting with prefix, ending with
// suffix, and of length between min and max (inclusive).
//
// Reference: https://github.com/torproject/tor/blob/master/src/common/crypto.c#L3172-L3181
//
//	/** Generate and return a new random hostname starting with <b>prefix</b>,
//	 * ending with <b>suffix</b>, and containing no fewer than
//	 * <b>min_rand_len</b> and no more than <b>max_rand_len</b> random base32
//	 * characters. Does not check for failure.
//	 *
//	 * Clip <b>max_rand_len</b> to MAX_DNS_LABEL_SIZE.
//	 **/
//	char *
//	crypto_random_hostname(int min_rand_len, int max_rand_len, const char *prefix,
//	                       const char *suffix)
//
func randomHostname(min, max int, prefix, suffix string) string {
	// Reference: https://github.com/torproject/tor/blob/master/src/common/util_format.h#L23-L25
	//
	//	/** Characters that can appear (case-insensitively) in a base32 encoding. */
	//	#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
	//	void base32_encode(char *dest, size_t destlen, const char *src, size_t srclen);
	//
	alphabet := "abcdefghijklmnopqrstuvwxyz234567"
	n := min + rand.Intn(max-min+1)
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return prefix + string(b) + suffix
}

// generateCertificateLifetime generates a reasonable looking certificate
// lifetime.
//
// Reference: https://github.com/torproject/tor/blob/master/src/or/router.c#L702-L717
//
//	  if (!lifetime) { /* we should guess a good ssl cert lifetime */
//
//	    /* choose between 5 and 365 days, and round to the day */
//	    unsigned int five_days = 5*24*3600;
//	    unsigned int one_year = 365*24*3600;
//	    lifetime = crypto_rand_int_range(five_days, one_year);
//	    lifetime -= lifetime % (24*3600);
//
//	    if (crypto_rand_int(2)) {
//	      /* Half the time we expire at midnight, and half the time we expire
//	       * one second before midnight. (Some CAs wobble their expiry times a
//	       * bit in practice, perhaps to reduce collision attacks; see ticket
//	       * 8443 for details about observed certs in the wild.) */
//	      lifetime--;
//	    }
//	  }
//
func generateCertificateLifetime() time.Duration {
	days := 5 + rand.Intn(360)
	wobble := rand.Intn(2)
	return time.Duration(days*24)*time.Hour - time.Duration(wobble)*time.Second
}

// generateCertificateIssued computes when we pretend a certificate was
// issued, given the total lifetime of the certificate.
func generateCertificateIssued(now time.Time, lifetime time.Duration) time.Time {
	// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L481-L487
	//
	//	  /* Make sure we're part-way through the certificate lifetime, rather
	//	   * than having it start right now. Don't choose quite uniformly, since
	//	   * then we might pick a time where we're about to expire. Lastly, be
	//	   * sure to start on a day boundary. */
	//	  time_t now = time(NULL);
	//	  start_time = crypto_rand_time_range(now - cert_lifetime, now) + 2*24*3600;
	//	  start_time -= start_time % (24*3600);
	//

	// BUG(mmcloughlin): certificate issued time not correctly computed
	return now.Add(-lifetime / 2)
}

// generateCertificateSerial generates a serial number for a certificate. This
// copies the convention of openssl and returns a 64-bit integer. Returns
// big.Int so it can be used with
// https://godoc.org/github.com/mmcloughlin/openssl#CertificateInfo.
//
// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L468-L470
//
//	  /* OpenSSL generates self-signed certificates with random 64-bit serial
//	   * numbers, so let's do that too. */
//	#define SERIAL_NUMBER_SIZE 8
//
// Reference: https://github.com/torproject/tor/blob/master/src/common/tortls.c#L502-L508
//
//	  { /* our serial number is 8 random bytes. */
//	    crypto_rand((char *)serial_tmp, sizeof(serial_tmp));
//	    if (!(serial_number = BN_bin2bn(serial_tmp, sizeof(serial_tmp), NULL)))
//	      goto error;
//	    if (!(BN_to_ASN1_INTEGER(serial_number, X509_get_serialNumber(x509))))
//	      goto error;
//	  }
//
func generateCertificateSerial() (*big.Int, error) {
	return generateCertificateSerialFromRandom(cryptorand.Reader)
}

func generateCertificateSerialFromRandom(r io.Reader) (*big.Int, error) {
	serialBytes := make([]byte, 8)
	_, err := io.ReadFull(r, serialBytes)
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(0)
	return serial.SetBytes(serialBytes), nil
}
