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

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <net/puzzle.h>

static inline u32 __zero_to_one(u32 value) {
    return value != 0 ? value : 1;
}
static inline u8 __down_to_u8(u16 val) {
    return (u8)(val < MAX_SPARE_GAP ? val : MAX_SPARE_GAP);
}

static const u32 NOT_FOUND = 500;

LIST_HEAD(policy_head);
LIST_HEAD(cache_head);
u32 dns_ip = 0;
EXPORT_SYMBOL(dns_ip);

u32 solve_puzzle(u8 type, u32 puzzle, u32 ip, u32 sub_ip) {

    u32 nonce = 0;

    switch(type) {
    case PZLTYPE_NONE:
        goto no_puzzle;
    case PZLTYPE_COPY:
        nonce = puzzle;
        break;
    case PZLTYPE_INC:
        nonce = puzzle + 1;
        break;
    case PZLTYPE_DNS_COPY:
        nonce = (puzzle ^ ip);
        break;
    case PZLTYPE_DNS_INC:
        nonce = (puzzle ^ ip) + 1;
    }

    return __zero_to_one(nonce);
no_puzzle:
    return 0;
}
EXPORT_SYMBOL(solve_puzzle);

static u32 puzzle_hash(u8 type, u32 puzzle, u32 nonce, u32 ip, u32 sub_ip) {
    return 0;
}

static u32 next_hash(u32 hash_value) {

    return __zero_to_one(hash_value + 1);
}
bool check_nonce(u8 type, u32 puzzle, u32 nonce) {
    printk(KERN_INFO "type : %u, puzzle : %u, nonce : %u", type, puzzle, nonce);

    return true;
}

u32 __generate_seed(u8 type, u32 ip) {
    /* TODO */
    return 10;
}

static bool find_puzzle_policy(u32 ip, struct puzzle_policy** ptr) {
    struct puzzle_policy* policy;
    struct list_head* head;
    list_for_each(head, &policy_head) {
        policy = list_entry(head, struct puzzle_policy, list);
        if(ip == policy->ip) {
            *ptr = policy;
            return true;
        }
    }

    return false;
}

static bool find_puzzle_cache(u32 ip, struct puzzle_cache** ptr) {
    struct puzzle_cache* cache;
    struct list_head* head;
    list_for_each(head, &cache_head) {
        cache = list_entry(head, struct puzzle_cache, list);
        if(ip == cache->ip) {
            *ptr = cache;
            return true;
        }
    }

    return false;
}

static void __print_policy_detail(struct puzzle_policy* policy) {

    printk(KERN_INFO "ip : %u.%u.%u.%u type : %d\n"
                , (policy->ip       )%256
                , (policy->ip  >>  8)%256
                , (policy->ip  >> 16)%256
                , (policy->ip  >> 24), policy->puzzle_type);
    printk(KERN_INFO "    | seed : %u , old_seed : %u\n", policy->seed, policy->seed_old);
    printk(KERN_INFO "    | assigned length : %u\n,", policy->assigned_length);
    printk(KERN_INFO "    | available : %u + %u\n,", policy->latest_pos, policy->spare_gap);
}

int print_policy_detail(u32 ip) {
    struct puzzle_policy* policy;
    printk(KERN_INFO "--puzzle_policy_detail--\n");
    if(find_puzzle_policy(ip, &policy))
        __print_policy_detail(policy);
    else
        return 0;
    printk(KERN_INFO "------------------------\n");
    return 1;
}

SYSCALL_DEFINE1(puzzle_detail_policy, u32, ip)
{
    return print_policy_detail(ip);
}


int print_policy(void) {
    struct puzzle_policy* policy;
    struct list_head* ptr;
    int count = 0;
    printk(KERN_INFO "--puzzle_policy_all-----\n");
    list_for_each(ptr, &policy_head) {
        policy = list_entry(ptr, struct puzzle_policy, list);
        __print_policy_detail(policy);
        count ++;
    }
    printk(KERN_INFO "---------------count : %d\n", count);

    return count;
}

SYSCALL_DEFINE0(puzzle_print_policy)
{
    return print_policy();
}

int print_cache(void) {
    struct puzzle_cache* cache;
    struct list_head* ptr;
    int count = 0;
    printk(KERN_INFO "--puzzle_cache-----\n");
    list_for_each(ptr, &cache_head) {
        cache = list_entry(ptr, struct puzzle_cache, list);
        printk(KERN_INFO "ip : %u.%u.%u.%u type : %d\n"
                    , (cache->ip       )%256
                    , (cache->ip  >>  8)%256
                    , (cache->ip  >> 16)%256
                    , (cache->ip  >> 24), cache->puzzle_type);
        printk(KERN_INFO "    | stored_puzzle : %u\n", cache->puzzle);
        count ++;
    }
    printk(KERN_INFO "---------------count : %d\n", count);

    return count;
}

SYSCALL_DEFINE0(puzzle_print_cache)
{
    return print_cache();
}


int add_policy(u32 ip, u8 puzzle_type, u16 assigned_length) {
    struct puzzle_policy* policy;
    if(find_puzzle_policy(ip, &policy))
        return -1;
    
    policy = kmalloc(sizeof(*policy), GFP_KERNEL);
    memset(policy, 0, sizeof(*policy));

    policy->ip = ip;
    policy->puzzle_type = puzzle_type;
    policy-> assigned_length = 2;

    list_add_tail(policy->list, &policy);


    return 0;
}

SYSCALL_DEFINE3(puzzle_add_policy, u32, ip, u8, puzzle_type, u16, assigned_length)
{
    return add_policy(ip, puzzle_type, assigned_length);
}

static void update_to_new_seed(struct puzzle_policy* policy, u32 new_seed) {

    policy->seed_old = policy->seed;
    policy->seed = new_seed;
    policy->spare_gap = __down_to_u8(policy->latest_pos);
    policy->latest_pos = policy->assigned_length;
}

int generate_new_seed(u32 ip) {
    struct puzzle_policy* policy;
    if(find_puzzle_policy(ip, &policy))
        return -1;

    update_to_new_seed(policy, __generate_seed(policy->puzzle_type, policy->ip));
    return 0;

}
EXPORT_SYMBOL(generate_new_seed);
SYSCALL_DEFINE1(puzzle_remake_seed, u32, ip)
{
    return generate_new_seed(ip);
}



bool find_pos_of_puzzle(u32 ip, u32 puzzle, u16* pos) {
    struct puzzle_policy* policy;
    u32 hash_value, iter, acceptable_pos;
    iter = 0;
    *pos = NOT_FOUND;
    if(unlikely(!find_puzzle_policy(ip, &policy))) 
        return false;
    hash_value = policy->seed;
    acceptable_pos = policy->latest_pos + policy->spare_gap;
    while( iter < policy->assigned_length ) {
        if(hash_value == puzzle) {
            if(*pos == NOT_FOUND || iter < acceptable_pos)
                *pos = iter;
        }
        iter ++;
        hash_value = next_hash(hash_value);
    }
    hash_value = policy->seed;
    while( iter < acceptable_pos ) {
        if(hash_value == puzzle) {
            *pos = iter;
        }
        iter++;
        hash_value = next_hash(hash_value);
    }
    return true;
}
EXPORT_SYMBOL(find_pos_of_puzzle);

int update_policy_from_config(void) {
    //TODO
    return 0;
}
SYSCALL_DEFINE0(puzzle_update_policy)
{
    return update_policy_from_config();
}

int update_policy(u32 ip, u8 type, u32 seed, u16 length) {
    struct puzzle_policy* policy;
    if(unlikely(!find_puzzle_policy(ip, &policy)))
        return -1;

    if(type) {
        if(type == PZLTYPE_NONE) {
            list_del(&(policy->list));
            kfree(policy);

            return 1;
        }
        policy->puzzle_type = type;
    }

    if(seed) {
        policy->seed = seed;
        update_to_new_seed(policy, seed);
    }

    return 0;
}

SYSCALL_DEFINE4(puzzle_edit_policy, u32, ip, u8, puzzle_type, u32, seed, u16, assigned_length)
{
    return update_policy(ip, puzzle_type, seed, assigned_length);
}

int update_policy_type(u32 ip, u8 type) {
    return update_policy(ip, type, 0, 0);
}
EXPORT_SYMBOL(update_policy_type);

int update_policy_length(u32 ip, u16 length) {
   return update_policy(ip, 0, 0, length);
}
EXPORT_SYMBOL(update_policy_length);

int update_puzzle_cache(u32 ip, u32 puzzle_type, u32 puzzle) {
    struct puzzle_policy* policy;
    if(unlikely(!find_puzzle_policy(ip, &policy)))
        return -1;

    return 0;
    /*TODO*/
}
EXPORT_SYMBOL(update_puzzle_cache);
