# Environment variable TORDIR should reference a checkout of the tor repo.

CC=clang

TOR_SUBDIRS=/ /src/common /src/ext /src/ext/ed25519/donna /src/ext/ed25519/ref10/ \
						/src/ext/keccak-tiny

TOR_CFLAGS=$(addprefix -I${TORDIR},${TOR_SUBDIRS})
OPENSSL_CFLAGS=`pkg-config --cflags openssl`
CFLAGS=${TOR_CFLAGS} ${OPENSSL_CFLAGS}

TOR_LDFLAGS=$(addprefix -L${TORDIR},${TOR_SUBDIRS})
OPENSSL_LDFLAGS=`pkg-config --libs openssl`
LDFLAGS=${TOR_LDFLAGS} ${OPENSSL_LDFLAGS} \
				-lor -lor-crypto -lor-ctime \
				-lcurve25519_donna -led25519_donna -led25519_ref10 -lkeccak-tiny

all: hybrid
