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

int add_hmac(unsigned char *packet_header, char *buf, int buf_len,
	      int nb_hmac);
int check_hmac(const unsigned char *packet, int packetlen, int bodylen);
