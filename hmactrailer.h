#define HMAC_TYPE 12
#define DIGEST_LEN 20
#define SHA1_BLOCK_SIZE 64

struct pseudo_header {
  int header_size;
  unsigned char *addr_src;
  unsigned char *addr_dest;
  int node_seq;
  int data_len;
};

int compute_hmac(unsigned char *packet_header, unsigned char *hmac,
		 const unsigned char *packet, int packetlen, int hash_type);
int add_hmac(unsigned char *packet_header, char *buf, int buf_len,
	      int nb_hmac);
int hmac_compare(const unsigned char *packet, int packetlen,
		 const unsigned char *hmac, int hmaclen);
int check_hmac(const unsigned char *packet, int packetlen, int bodylen);
