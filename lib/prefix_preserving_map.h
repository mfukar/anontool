#ifndef _PP_MAP_H_
#define _PP_MAP_H_
typedef struct node node_t, *node_p;    /* type of a tree node */

struct node {
    u_long input,          /* input value */
        output;         /* output value */
    node_p  down[2];        /* children */
};

typedef struct nodehdr nodehdr_t, *nodehdr_p;   /* type of a tree */

struct nodehdr {
    u_long
        flags,          /* see below */
        addr_mask,      /* mask of bits to copy from input */
        counter,        /* for NH_FL_COUNTER */
        bump,           /* amount by which to bump counter */
        cur_input;      /* what address is currently being masked */
    node_p
        head;
};

#define NH_FL_RANDOM_PROPAGATE  1       /* propagate random number down */
#define NH_FL_COUNTER           2       /* bump a counter */

#define EXTRACT_BIT(value,bitno) (((value)>>(32-(bitno)))&1)

void lookup_init(nodehdr_p hdr);

#endif
