struct anm {
  unsigned char from[16];
  struct interface ifp;
  unsigned int last_ts;
  unsigned short last_pc;
};

struct anm *find_anm(const unsigned char *from, const struct interface *ifp);
int add_anm(unsigned char *from, struct interface *ifp,
               unsigned int last_ts, unsigned short last_pc);
