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
};

struct puzzle_cache {
	u32 ip;
	u8 puzzle_type;
	u32 puzzle;

	struct list_head list;
};

extern u32 dns_ip;

u32 solve_puzzle(u8 type, u32 puzzle, u32 client_ip, u32 ip);
int generate_new_seed(u32 ip);
bool find_pos_of_puzzle(u32 ip, u32 puzzle, u16* pos);
int update_policy_type(u32 ip, u8 type);
int update_policy_length(u32 ip, u16 length);
int update_puzzle_cache(u32 ip, u32 puzzle_type, u32 puzzle);

#endif