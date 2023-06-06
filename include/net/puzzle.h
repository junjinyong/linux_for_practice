#ifndef _PUZZLE_H
#define _PUZZLE_H

#include <linux/list.h>

#define PZLTYPE_NONE 1
#define PZLTYPE_LOCAL 2
#define PZLTYPE_DNS 3

#define PZLTYPE_MAX 63

#define MAX_ASSIGNED_LENGTH 255
#define MAX_SPARE_GAP 63

struct puzzle_policy {
	u32 ip;
	u32 threshold;
	u32 seed;
	u32 seed_old;
	u16 assigned_length;
	u16 latest_pos; 
	u16 spare_gap;

	struct list_head list;
};

struct puzzle_cache {
	u32 ip;
	u8 puzzle_type;
	u32 puzzle;
	u32 threshold;

	struct list_head list;
};

u32 do_puzzle_solve(u32 threshold, u32 puzzle, u32 target_ip, u32 target_port, u8 puzzle_type);
int check_puzzle(u8 type, u32 puzzle, u32 nonce, u32 ip, u32 port, u32 policy_ip);
u32 generate_new_seed(u32 ip);
long update_policy(u32 ip, u32 seed, u16 length, u32 threshold);
int update_puzzle_cache(u32 ip, u8 type, u32 puzzle, u32 threshold);
bool find_puzzle_policy(u32 ip, struct puzzle_policy** ptr);
bool find_puzzle_cache(u32 ip, struct puzzle_cache** ptr);
long print_policy(void);
long add_policy(u32 ip, u16 assigned_length, u32 threshold);
u32 get_last_hash_chain(struct puzzle_policy* policy);

u8 get_puzzle_type(void);
u8 set_puzzle_type(u8 puzzle_type);
long get_puzzle_dns(u32* ip, u32* port);


#endif
