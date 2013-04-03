#include <malloc.h>
#include <stdio.h>

struct test_struct {
    int i_field;
    long l_field;

    union {
        char x;
        long y[10];
    }unamed_union;

    int b_field1:1,
        b_field2:1,
        b_field3:1;
};

typedef struct test_struct test_struct_t;
typedef struct test_struct *test_struct_ptr_t;

const test_struct_t global_variable1;
volatile test_struct_t *global_variable2;
struct test_struct global_variable3;
struct test_struct *global_variable4;
struct another_test_struct *global_variable5;

typedef void (*fn_t)(int arg1, test_struct_t ** arg2);

typedef struct another_test_struct {
    char c_field;

    test_struct_t s_field;
    int i_field;

    test_struct_t *sp_field;

    char *****too_many_pointer_field;
    struct inside_struct{
        char pad_field[3];
        test_struct_ptr_t *pp_field;
    }inside_field;

    void *pointer_array[11];
    fn_t function_pointers[3];

    const char const_field;
    volatile const char * const_volatile_field;

    struct another_test_struct *self_ref_field[];

}another_test_struct_t;

void 
recursive_function(int i)
{
    if ( i < 10 ) {
        recursive_function(i+1);
    } else {
        char *crash=0;
        *crash = 0;
    }
}

void __attribute__ ((noreturn))
static_function()
{
    char name[]=__FILE__;
    recursive_function(0);
    __builtin_unreachable();
}

#define C(n, m)\
static void call_me##n(){ call_me##m(); }

static void call_me6()
{
    static_function();
}

C(5,6)
C(4,5)
C(3,4)
C(2,3)
C(1,2)

void
call_me()
{
    call_me1();
}

void
test_func(volatile char *para1)
{
    unsigned long stack_arg;
    register long reg_arg, reg_arg1;
    volatile char *memory_arg = para1;
    test_struct_t t;

    stack_arg = *memory_arg;
    reg_arg = *memory_arg;
    reg_arg += stack_arg;
    t.l_field = reg_arg;
    reg_arg1 = reg_arg;

    *memory_arg = reg_arg;

    call_me();
}

int
main(int argc, char *argv[])
{
    int i;
    if (argc > 1) {
        printf("%d\n", argc);
    } else {
        char *stack_arg[10];
        for (i=0;i<10;i++) {
            stack_arg[i] = malloc(100);
            if (stack_arg[i] == NULL) {
                printf("malloc failed");
                return 1;
            }

        }
        for (i=0;i<10;i++) {
            test_func(stack_arg[i]);
        }
    }
    return 0;
}

