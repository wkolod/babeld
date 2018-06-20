#define TSPC_TYPE 11
#define HMAC_TYPE 12
#define DIGEST_LEN 20
#define SHA1_BLOCK_SIZE 64


int add_hmac(unsigned char *packet_header, struct buffered *message,
	     int nb_hmac);
int check_tspc(const unsigned char *packet, int bodylen,
               unsigned char *from, struct interface *ifp);
int check_echo_age(struct timeval *last_echo, struct timeval *now);
int check_echo(unsigned int ts, unsigned char *last_tspc);
int check_hmac(const unsigned char *packet, int packetlen, int bodylen,
	       unsigned char *addr_src, unsigned char *addr_dst);
