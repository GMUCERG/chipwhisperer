#ifndef crypto_hash_h
#define crypto_hash_h

#ifdef __cplusplus
extern "C" {
#endif

int crypto_hash(
	unsigned char *out,
	const unsigned char *in,
	unsigned long long inlen
	);

#ifdef __cplusplus
}
#endif

#endif
