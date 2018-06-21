#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <time.h>

#include "babeld.h"
#include "interface.h"
#include "neighbour.h"
#include "util.h"
#include "hmac.h"
#include "configuration.h"
#include "kernel.h"
#include "anm.h"
#include "message.h"

struct key **keys = NULL;
int numkeys = 0, maxkeys = 0;

struct key *
find_key(const char *id)
{
    int i;
    for(i = 0; i < numkeys; i++) {
	if(strcmp(keys[i]->id, id) == 0)
            return retain_key(keys[i]);
    }
    return NULL;
}

struct key *
retain_key(struct key *key)
{
    assert(key->ref_count < 0xffff);
    key->ref_count++;
    return key;
}

void
release_key(struct key *key)
{
    assert(key->ref_count > 0);
    key->ref_count--;
    /* XXX free if zero */
}

struct key *
add_key(char *id, int type, unsigned char *value)
{
    struct key *key;

    assert(value != NULL && type != 0);

    key = find_key(id);
    if(key) {
        if(type == AUTH_TYPE_NONE) {
	    release_key(key);
	    return NULL;
	}
	key->type = type;
	key->value = value;
	return key;
    }

    if(type == AUTH_TYPE_NONE)
	return NULL;
    if(numkeys >= maxkeys) {
	struct key **new_keys;
	int n = maxkeys < 1 ? 8 : 2 * maxkeys;
	new_keys = realloc(keys, n * sizeof(struct key*));
	if(new_keys == NULL)
	    return NULL;
	maxkeys = n;
	keys = new_keys;
    }

    key = calloc(1, sizeof(struct key));
    if(key == NULL)
	return NULL;
    key->id = id;
    key->type = type;
    key->value = value;

    keys[numkeys++] = key;
    numkeys++;
    return key;
}

static int
compute_hmac(unsigned char *src, unsigned char *dst,
	     unsigned char *packet_header, unsigned char *hmac,
	     const unsigned char *body, int bodylen, struct key *key)
{
    SHA_CTX inner_ctx;
    RIPEMD160_CTX inner_ctx2;
    SHA_CTX outer_ctx;
    RIPEMD160_CTX outer_ctx2;
    SHA_CTX key_ctx;
    RIPEMD160_CTX key_ctx2;

    unsigned char inner_hash[SHA_DIGEST_LENGTH];
    unsigned char key_hash[SHA_DIGEST_LENGTH];
    unsigned char inner_key_pad[SHA1_BLOCK_SIZE];
    unsigned char outer_key_pad[SHA1_BLOCK_SIZE];

    int i;
    int keylen;

    switch(key->type) {
    case 1:
	keylen = sizeof(key->value);
	memcpy(key_hash, key->value, keylen);
	if(keylen > SHA1_BLOCK_SIZE) {
	    SHA1_Init(&key_ctx);
	    SHA1_Update(&key_ctx, key->value, keylen);
	    SHA1_Final(key_hash, &key_ctx);
	    keylen = SHA_DIGEST_LENGTH;
	}
	for(i = 0; i < keylen; i++) {
	    inner_key_pad[i] = key_hash[i]^0x36;
	}
	for(i = keylen; i < SHA1_BLOCK_SIZE; i++) {
	    inner_key_pad[i] = 0x36;
	}
	SHA1_Init(&inner_ctx);
	SHA1_Update(&inner_ctx, inner_key_pad, SHA1_BLOCK_SIZE);
	SHA1_Update(&inner_ctx, dst, 16);
	SHA1_Update(&inner_ctx, src, 16);
	SHA1_Update(&inner_ctx, packet_header, 4);
	SHA1_Update(&inner_ctx, body, bodylen);
	SHA1_Final(inner_hash, &inner_ctx);

	for(i = 0; i < keylen; i++) {
	    outer_key_pad[i] = key_hash[i]^0x5c;
	}
	for(i = keylen; i < SHA1_BLOCK_SIZE; i++) {
	    outer_key_pad[i] = 0x5c;
	}
	SHA1_Init(&outer_ctx);
	SHA1_Update(&outer_ctx, outer_key_pad, SHA1_BLOCK_SIZE);
	SHA1_Update(&outer_ctx, inner_hash, SHA_DIGEST_LENGTH);
	SHA1_Final(hmac, &outer_ctx);
	return SHA_DIGEST_LENGTH;
    case 2:
	keylen = sizeof(key->value);
	memcpy(key_hash, key->value, keylen);
	if(keylen > RIPEMD160_BLOCK_SIZE) {
	    RIPEMD160_Init(&key_ctx2);
	    RIPEMD160_Update(&key_ctx2, key->value, keylen);
	    RIPEMD160_Final(key_hash, &key_ctx2);
	    keylen = RIPEMD160_DIGEST_LENGTH;
	}
	for(i = 0; i < keylen; i++) {
	    inner_key_pad[i] = key_hash[i]^0x36;
	}
	for(i = keylen; i < RIPEMD160_BLOCK_SIZE; i++) {
	    inner_key_pad[i] = 0x36;
	}
	RIPEMD160_Init(&inner_ctx2);
	RIPEMD160_Update(&inner_ctx2, inner_key_pad, RIPEMD160_BLOCK_SIZE);
	RIPEMD160_Update(&inner_ctx2, dst, 16);
	RIPEMD160_Update(&inner_ctx2, src, 16);
	RIPEMD160_Update(&inner_ctx2, packet_header, 4);
	RIPEMD160_Update(&inner_ctx2, body, bodylen);
	RIPEMD160_Final(inner_hash, &inner_ctx2);

	for(i = 0; i < keylen; i++) {
	    outer_key_pad[i] = key_hash[i]^0x5c;
	}
	for(i = keylen; i < RIPEMD160_BLOCK_SIZE; i++) {
	    outer_key_pad[i] = 0x5c;
	}
	RIPEMD160_Init(&outer_ctx2);
	RIPEMD160_Update(&outer_ctx2, outer_key_pad, RIPEMD160_BLOCK_SIZE);
	RIPEMD160_Update(&outer_ctx2, inner_hash, RIPEMD160_DIGEST_LENGTH);
	RIPEMD160_Final(hmac, &outer_ctx2);
	RIPEMD160(body, bodylen, hmac);
	return RIPEMD160_DIGEST_LENGTH;
    default:
        return -1;
    }
}

int
add_hmac(unsigned char *packet_header, struct buffered *message, int nb_hmac)
{
    int hmaclen;
    int hmac_space = 0;
    int buf_len = message->len;
    char *buf = message->buf;
    unsigned char *addr_src = message->ll;
    unsigned char *addr_dst = message->sin6.sin6_addr.s6_addr;
    int i = buf_len;

    debugf("add_hmac %s -> %s\n",
	   format_address(addr_src), format_address(addr_dst));

    while (nb_hmac > 0){
        buf[i] = HMAC_TYPE;
	buf[i+1] = DIGEST_LEN;
	hmaclen = compute_hmac(addr_src, addr_dst, packet_header,
			       (unsigned char *)buf + i + 2,
			       (unsigned char *)buf, buf_len, message->key);
	if(hmaclen < 0) {
	    return -1;
	}
	i += hmaclen + 2;
	hmac_space += hmaclen + 2;
	nb_hmac--;
    }
    return hmac_space;
}


static int
compare_hmac(unsigned char *src, unsigned char *dst,
	     const unsigned char *packet, int bodylen,
	     const unsigned char *hmac, int hmaclen)
{
    unsigned char true_hmac[DIGEST_LEN];
    int true_hmaclen;
    unsigned char packet_header[4] = {packet[0], packet[1], packet[2],
				      packet[3]};
    int i;
    for(i = 0; i < numkeys; i++) {
	true_hmaclen = compute_hmac(src, dst, packet_header, true_hmac,
					packet + 4, bodylen, keys[i]);
	if(true_hmaclen != hmaclen) {
	    fprintf(stderr, "Length inconsistency of two hmacs.\n");
	    return -1;
	}
	if(memcmp(true_hmac, hmac, hmaclen) == 0)
            return 1;
    }
    return 0;
}

int
check_tspc(const unsigned char *packet, int bodylen,
	   unsigned char *from, struct interface *ifp)
{
    int i, nb_tspc;
    const unsigned char *message;
    unsigned char type, len;
    struct anm *anm;
    anm = find_anm(from, ifp);
    if(anm == NULL) {
	unsigned char tspc_init[6];
	memset(tspc_init, 0, 6);
	anm = add_anm(from, ifp, tspc_init);
        if(anm == NULL) {
	    fprintf(stderr, "Couldn't create ANM.\n");
            return -1;
	}
    }
    nb_tspc = 0;
    i = 0;
    while(i < bodylen) {
	message = packet + 4 + i;
	type = message[0];
	if(type == MESSAGE_PAD1) {
	    i++;
	    continue;
	}
	len = message[1];
	if(type == TSPC_TYPE) {
            unsigned char tspc[6];
	    memcpy(tspc, message + 2, 6);
	    if(memcmp(anm->last_tspc, tspc, 6) >= 0)
		return 0;
	    memcpy(anm->last_tspc, tspc, 6);
	    nb_tspc++;
        }
	i += len + 2;
    }
    if(nb_tspc != 1) {
	fprintf(stderr, "Refuse TS/PC.\n");
	return 0;
    }
    return 1;
}

int
check_echo_age(struct timeval *last_echo, struct timeval *now)
{
    struct timeval deadline;
    timeval_add_msec(&deadline, last_echo, 128 * 1000);
    return timeval_compare(now, &deadline) <= 0;
}

int
check_echo(unsigned int ts, unsigned char *last_tspc)
{
    unsigned int first;
    unsigned int last = 0;
    unsigned int last_ts;
    memcpy(&last_ts, last_tspc, 4);
    DO_NTOHL(last, &last_ts);
    memcpy(&first, &last, 4);
    first -= 30;
    if(first < 0)
	first = 0;
    if(ts >= first && ts <= last){
	return 1;
    }
    fprintf(stderr, "Invalid echo.\n");
    return 0;
}

int
check_hmac(const unsigned char *packet, int packetlen, int bodylen,
	   unsigned char *addr_src, unsigned char *addr_dst)
{
    int i = bodylen + 4;
    int hmaclen;

    debugf("check_hmac %s -> %s\n",
	   format_address(addr_src), format_address(addr_dst));
    while(i < packetlen) {
        hmaclen = packet[i+1];
        if(packet[i] == HMAC_TYPE) {
	    if(hmaclen + i > packetlen) {
	        fprintf(stderr, "Received truncated hmac.\n");
		return -1;
	    }
	    if(compare_hmac(addr_src, addr_dst, packet, bodylen,
			    packet + i + 2 , hmaclen)) {
		return 1;
	    }
	}
	i += hmaclen + 2;
    }
    return 0;
}
