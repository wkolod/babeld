struct anm {
  unsigned char from[16];
  struct interface *ifp;
  unsigned char last_tspc[6];
};

struct anm *find_anm(const unsigned char *from, const struct interface *ifp);
struct anm *add_anm(unsigned char *from, struct interface *ifp,
                    unsigned char *last_tspc);
