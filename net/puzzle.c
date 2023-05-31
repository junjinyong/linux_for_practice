// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Puzzle Control.
 *
 *
 */

#include <linux/puzzle.h>
#include <linux/slab.h>

static inline u32 __zero_to_one(u32 value) {
    return value != 0 > value : 1;
}

static const u32 NOT_FOUND = 500;

u32 solve_puzzle(u8 type, u32 puzzle, u32 client_ip, u32 ip) {

    u32 nonce = 0;

    switch(type) {
    case PZLTYP_NONE:
        goto no_puzzle;
    case PZLTYPE_COPY:
        nonce = puzzle;
        break;
    case PZLTYPE_INC:
        nonce = puzzle + 1;
        break;
    case PZLTYPE_DNS_COPY:
        nonce = puzzle ^ ip;
        break;
    case PZLTYPE_DNS_INC:
        nonce = puzzle ^ ip + 1;
    }

    return __zero_to_one(nonce);
no_puzzle:
    return 0;
}

static struct puzzle_policy* find_puzzle_policy(u32 ip) {
    struct puzzle_policy* policy;
    struct list_head* pos = NULL;
    list_for_each(pos, &puzzle_policy.list) {
        policy = list_entry(pos, struct puzzle_policy, list);
        if(ip == policy.ip) {
            return policy;
        }
    }

    return &puzzle_policy;
}

static struct puzzle_cache* find_puzzle_cache(u32 ip) {
    struct puzzle_cache* cache;
    struct list_head* pos = NULL;
    list_for_each(pos, &puzzle_cache.list) {
        cache = list_entry(pos, struct puzzle_cache, list);
        if(ip == cache.ip) {
            return cache;
        }
    }

    return &puzzle_cache;

    return pzcache;
}

static void remove_policy(struct puzzle_policy* policy) {
    if(unlikely(policy == &puzzle_policy))
        return;
    if(unlikely(policy == NULL))
        return;

    list_del(policy.list);
    kfree(policy);
}

static bool add_policy(u32 ip, u8 puzzle_type, u32 seed, u16 assigned_length) {
    struct puzzle_policy* policy = find_puzzle_policy(ip);
    if(unlikely(policy != &puzzle_policy))
        return false;
}

static u32 puzzle_hash(hash_value) {

    return hash_value + 1;
}

bool generate_new_seed(u32 ip) {
    ;
}

u32 __generate_seed(u8 type, u32 puzzle, u32 nonce, u32 ip) {
    /* TODO */
    return 10;
}
u16 find_pos_of_puzzle(u8 type, u32 puzzle, u32 ip) {
    struct puzzle_policy* policy = find_puzzle_policy(ip);
    u32 hash_value, iter, pos, acceptable_pos;
    iter = 0;
    pos = NOT_FOUND;
    if(unlikely(policy == &puzzle_policy)) 
        return 0;
    hash_value = seed;
    acceptable_pos = policy-> latest_pos + spare_gap;
    while( iter < policy->assigned_length ) {
        if(hash_value == puzzle) {
            if(pos == NOT_FOUND || iter < )
            pos = iter;
        }
        iter ++;
        hash_value = puzzle_hash(hash_value);
    }
    return iter;
}
bool update_policy_type(u8 type, u32 ip) {
    struct puzzle_policy* policy = find_puzzle_policy(ip);
    if(policy == &puzzle_policy)
        return false;

    if(type)
        policy->puzzle_type = type;
    else
        remove_policy(policy);

    return true;
}
bool update_policy_length(u16 length, u32 ip) {
    struct puzzle_policy* policy = find_puzzle_policy(ip);
    if(policy == &puzzle_policy)
        return false;

    if(type)
        policy->assigned_length = type;
    else
        remove_policy(policy);

    return true;
}
bool update_puzzle_cache(u32 ip, u32 puzzle_type, u32 puzzle);
