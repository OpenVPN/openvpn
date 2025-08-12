
struct multi_address
{
    int i, f;
    char s[64];
    time_t t;
    in_addr_t v[MAX_THREADS];
};

struct multi_pointer
{
    int i, n, h, x, z;
    struct context *c;
    struct multi_context **m;
    struct multi_context *p;
    struct multi_address *a;
    pthread_mutex_t l;
};

struct multi_info
{
    int n, z;
    struct multi_address *a;
};

struct multi_args
{
    int i, n;
    struct context *c;
    struct multi_pointer *p;
};
