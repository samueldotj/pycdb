struct test_struct {
    volatile int i;
    long l;
};
typedef struct test_struct test_struct_t;

static test_struct_t *
init_struct(test_struct_t *t)
{
    t->i=0;
    t->l=0;
}

int
get_struct()
{
    volatile test_struct_t t;
    init_struct((test_struct_t *)&t);
    if (t.i)
        return 0;
    else
        return 1;
}

