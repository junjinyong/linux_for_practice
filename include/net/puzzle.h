/* */
/*
 * 
 * Author: Minjun Sun <nebe.ep@snu.ac.kr>
 */

#ifndef _PUZZLE_H
#define _PUZZLE_H

#include <linux/list.h>

#define PZLTYPE_NONE 1
#define PZLTYPE_COPY 2
#define PZLTYPE_INC 3

#define PZLTYPE_DNS_COPY 21
#define PZLTYPE_DNS_INC 22

#define PZLTYPE_MAX 63

#define MAX_ASSIGNED_LENGTH 255
#define MAX_SPARE_GAP 63

struct puzzle_policy {
	u32 ip;
	u8 puzzle_type;
	u32 seed;
	u32 seed_old;
	u16 assigned_length;
	u16 latest_pos; 
	u8 spare_gap;

	struct list_head list;
}

struct puzzle_cache {
	u32 ip;
	u8 puzzle_type;
	u32 puzzle;

	struct list_head list;
}

static struct puzzle_policy puzzle_policy;
static struct puzzle_cache puzzle_cache;
static u32 dns_ip = 0;

INIT_LIST_HEAD(&puzzle_policy.list);
INIT_LIST_HEAD(&puzzle_cache.list);

u32 solve_puzzle(u8 type, u32 puzzle,, u32 client_ip, u32 ip);
bool generate_new_seed(u32 ip);
u16 find_pos_of_puzzle(u8 type, u32 puzzle, u32 ip);
bool update_policy_type(u8 type, u32 ip);
bool update_policy_length(u16 length, u32 ip);
bool update_puzzle_cache(u32 ip, u32 puzzle_type, u32 puzzle);

inline u32 get_dns_ip() { return dns_ip; }
inline void set_dns_ip(u32 ip) { dns_ip = ip; }


#endif