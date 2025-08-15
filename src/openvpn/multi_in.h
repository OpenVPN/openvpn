
struct multi_address
{
    int i;
    char s[32];
    time_t t;
};

struct multi_pointer
{
    int x, y;
    struct context *c;
    struct multi_context **m;
    struct multi_context *p;
    struct multi_address *a;
    pthread_mutex_t *l;
};

struct multi_args
{
    int i;
    struct context *c;
    struct multi_pointer *p;
};
