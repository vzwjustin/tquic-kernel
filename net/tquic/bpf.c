// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC BPF struct_ops support for pluggable path schedulers
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module enables BPF programs to implement custom TQUIC path
 * schedulers, similar to how TCP allows BPF congestion control.
 * Users can write schedulers in BPF C and load them at runtime.
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/tquic.h>

/* BPF struct_ops for TQUIC scheduler */
static struct bpf_struct_ops bpf_tquic_sched_ops;

/* BTF type IDs */
static const struct btf_type *tquic_sched_type;
static const struct btf_type *tquic_sched_ops_type;
static const struct btf_type *tquic_path_type;
static const struct btf_type *tquic_sched_ctx_type;
static u32 tquic_sched_id, tquic_path_id, tquic_sched_ctx_id;

/*
 * Initialize BTF type lookups
 */
static int bpf_tquic_sched_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "tquic_scheduler", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_id = type_id;
	tquic_sched_type = btf_type_by_id(btf, tquic_sched_id);

	type_id = btf_find_by_name_kind(btf, "tquic_path", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_path_id = type_id;
	tquic_path_type = btf_type_by_id(btf, tquic_path_id);

	type_id = btf_find_by_name_kind(btf, "tquic_sched_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_ctx_id = type_id;
	tquic_sched_ctx_type = btf_type_by_id(btf, tquic_sched_ctx_id);

	type_id = btf_find_by_name_kind(btf, "tquic_scheduler_ops", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_ops_type = btf_type_by_id(btf, type_id);

	return 0;
}

/*
 * Validate BPF program access to TQUIC structures
 */
static bool bpf_tquic_sched_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	/* Allow read access to tquic_scheduler, tquic_path, tquic_sched_ctx */
	if (base_type(info->reg_type) == PTR_TO_BTF_ID &&
	    !bpf_type_has_unsafe_modifiers(info->reg_type)) {
		/* Promote generic pointers to specific TQUIC types */
		if (info->btf_id == tquic_sched_id ||
		    info->btf_id == tquic_path_id ||
		    info->btf_id == tquic_sched_ctx_id)
			return true;
	}

	return true;
}

/*
 * Validate struct member access for writes
 */
static int bpf_tquic_sched_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);

	/* Allow writes to scheduler private data area */
	if (t == tquic_sched_type) {
		switch (off) {
		case offsetof(struct tquic_scheduler, priv_data):
			end = offsetofend(struct tquic_scheduler, priv_data);
			break;
		case offsetof(struct tquic_scheduler, rr_counter):
			end = offsetofend(struct tquic_scheduler, rr_counter);
			break;
		default:
			bpf_log(log, "no write support to tquic_scheduler at off %d\n", off);
			return -EACCES;
		}

		if (off + size > end) {
			bpf_log(log, "write access beyond member bounds\n");
			return -EACCES;
		}
		return 0;
	}

	/* Allow writes to path congestion state */
	if (t == tquic_path_type) {
		switch (off) {
		case offsetof(struct tquic_path, weight):
			end = offsetofend(struct tquic_path, weight);
			break;
		case offsetof(struct tquic_path, priority):
			end = offsetofend(struct tquic_path, priority);
			break;
		case offsetof(struct tquic_path, schedulable):
			end = offsetofend(struct tquic_path, schedulable);
			break;
		default:
			bpf_log(log, "no write support to tquic_path at off %d\n", off);
			return -EACCES;
		}

		if (off + size > end) {
			bpf_log(log, "write access beyond member bounds\n");
			return -EACCES;
		}
		return 0;
	}

	bpf_log(log, "only read is supported for this type\n");
	return -EACCES;
}

/*
 * BPF kfuncs for TQUIC scheduler programs
 */

/* Get the primary path from path manager */
__bpf_kfunc struct tquic_path *bpf_tquic_get_primary_path(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return NULL;
	return sched->pm->primary_path;
}

/* Get the backup path from path manager */
__bpf_kfunc struct tquic_path *bpf_tquic_get_backup_path(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return NULL;
	return sched->pm->backup_path;
}

/* Get path count */
__bpf_kfunc u32 bpf_tquic_get_path_count(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return 0;
	return sched->pm->path_count;
}

/* Get active path count */
__bpf_kfunc u32 bpf_tquic_get_active_path_count(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return 0;
	return sched->pm->active_path_count;
}

/* Check if path is usable */
__bpf_kfunc bool bpf_tquic_path_is_usable(struct tquic_path *path)
{
	return tquic_path_is_usable(path);
}

/* Check if path is active */
__bpf_kfunc bool bpf_tquic_path_is_active(struct tquic_path *path)
{
	return tquic_path_is_active(path);
}

/* Get path smoothed RTT in microseconds */
__bpf_kfunc u64 bpf_tquic_path_get_srtt_us(struct tquic_path *path)
{
	if (!path)
		return 0;
	return ktime_to_us(path->rtt.smoothed_rtt);
}

/* Get path minimum RTT in microseconds */
__bpf_kfunc u64 bpf_tquic_path_get_min_rtt_us(struct tquic_path *path)
{
	if (!path)
		return 0;
	return ktime_to_us(path->rtt.min_rtt);
}

/* Get path estimated bandwidth in bytes/sec */
__bpf_kfunc u64 bpf_tquic_path_get_bandwidth(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->bandwidth.estimated_bw;
}

/* Get path congestion window */
__bpf_kfunc u64 bpf_tquic_path_get_cwnd(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->congestion.cwnd;
}

/* Get path bytes in flight */
__bpf_kfunc u64 bpf_tquic_path_get_bytes_in_flight(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->congestion.bytes_in_flight;
}

/* Get path loss rate (per 10000) */
__bpf_kfunc u32 bpf_tquic_path_get_loss_rate(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->loss.current_loss_rate;
}

/* Check if path can send given bytes */
__bpf_kfunc bool bpf_tquic_path_can_send(struct tquic_path *path, u32 bytes)
{
	return tquic_path_can_send(path, bytes);
}

/* Iterate to next path (for BPF loops) */
__bpf_kfunc struct tquic_path *bpf_tquic_path_next(struct tquic_scheduler *sched,
						   struct tquic_path *path)
{
	struct list_head *next;

	if (!sched || !sched->pm)
		return NULL;

	if (!path) {
		/* Return first path */
		if (list_empty(&sched->pm->paths))
			return NULL;
		return list_first_entry(&sched->pm->paths, struct tquic_path, list);
	}

	next = path->list.next;
	if (next == &sched->pm->paths)
		return NULL;

	return list_entry(next, struct tquic_path, list);
}

BTF_KFUNCS_START(bpf_tquic_sched_kfunc_ids)
BTF_ID_FLAGS(func, bpf_tquic_get_primary_path)
BTF_ID_FLAGS(func, bpf_tquic_get_backup_path)
BTF_ID_FLAGS(func, bpf_tquic_get_path_count)
BTF_ID_FLAGS(func, bpf_tquic_get_active_path_count)
BTF_ID_FLAGS(func, bpf_tquic_path_is_usable)
BTF_ID_FLAGS(func, bpf_tquic_path_is_active)
BTF_ID_FLAGS(func, bpf_tquic_path_get_srtt_us)
BTF_ID_FLAGS(func, bpf_tquic_path_get_min_rtt_us)
BTF_ID_FLAGS(func, bpf_tquic_path_get_bandwidth)
BTF_ID_FLAGS(func, bpf_tquic_path_get_cwnd)
BTF_ID_FLAGS(func, bpf_tquic_path_get_bytes_in_flight)
BTF_ID_FLAGS(func, bpf_tquic_path_get_loss_rate)
BTF_ID_FLAGS(func, bpf_tquic_path_can_send)
BTF_ID_FLAGS(func, bpf_tquic_path_next)
BTF_KFUNCS_END(bpf_tquic_sched_kfunc_ids)

static const struct btf_kfunc_id_set bpf_tquic_sched_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_tquic_sched_kfunc_ids,
};

/*
 * Get BPF function prototypes for TQUIC scheduler programs
 */
static const struct bpf_func_proto *
bpf_tquic_sched_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_ktime_get_coarse_ns:
		return &bpf_ktime_get_coarse_ns_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static const struct bpf_verifier_ops bpf_tquic_sched_verifier_ops = {
	.get_func_proto		= bpf_tquic_sched_get_func_proto,
	.is_valid_access	= bpf_tquic_sched_is_valid_access,
	.btf_struct_access	= bpf_tquic_sched_btf_struct_access,
};

/*
 * Initialize member from userspace BPF program
 */
static int bpf_tquic_sched_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	const struct tquic_scheduler_ops *uops;
	struct tquic_scheduler_ops *ops;
	u32 moff;

	uops = (const struct tquic_scheduler_ops *)udata;
	ops = (struct tquic_scheduler_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct tquic_scheduler_ops, name):
		if (bpf_obj_name_cpy(ops->name, uops->name,
				     sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

/*
 * Register BPF scheduler with TQUIC
 */
static int bpf_tquic_sched_reg(void *kdata, struct bpf_link *link)
{
	return tquic_scheduler_register(kdata);
}

/*
 * Unregister BPF scheduler from TQUIC
 */
static void bpf_tquic_sched_unreg(void *kdata, struct bpf_link *link)
{
	tquic_scheduler_unregister(kdata);
}

/*
 * Validate BPF scheduler before registration
 */
static int bpf_tquic_sched_validate(void *kdata)
{
	struct tquic_scheduler_ops *ops = kdata;

	/* select_path is required */
	if (!ops->select_path)
		return -EINVAL;

	return 0;
}

/*
 * Stub functions for BPF scheduler operations
 * These are called when BPF program doesn't implement the callback
 */
static int __bpf_tquic_sched_init(struct tquic_scheduler *sched)
{
	return 0;
}

static void __bpf_tquic_sched_release(struct tquic_scheduler *sched)
{
}

static struct tquic_path *__bpf_tquic_sched_select_path(struct tquic_scheduler *sched,
							struct tquic_sched_ctx *ctx)
{
	/* Default: return primary path */
	if (sched && sched->pm)
		return sched->pm->primary_path;
	return NULL;
}

static void __bpf_tquic_sched_on_packet_sent(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     u32 bytes)
{
}

static void __bpf_tquic_sched_on_packet_acked(struct tquic_scheduler *sched,
					      struct tquic_path *path,
					      u32 bytes, ktime_t rtt)
{
}

static void __bpf_tquic_sched_on_packet_lost(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     u32 bytes)
{
}

static void __bpf_tquic_sched_on_path_change(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     enum tquic_path_event event)
{
}

static int __bpf_tquic_sched_set_param(struct tquic_scheduler *sched,
				       int param, u64 value)
{
	return -EOPNOTSUPP;
}

static void __bpf_tquic_sched_get_stats(struct tquic_scheduler *sched,
					void *stats, size_t len)
{
}

/*
 * Default BPF scheduler operations (stubs)
 */
static struct tquic_scheduler_ops __bpf_ops_tquic_scheduler_ops = {
	.init		= __bpf_tquic_sched_init,
	.release	= __bpf_tquic_sched_release,
	.select_path	= __bpf_tquic_sched_select_path,
	.on_packet_sent	= __bpf_tquic_sched_on_packet_sent,
	.on_packet_acked = __bpf_tquic_sched_on_packet_acked,
	.on_packet_lost	= __bpf_tquic_sched_on_packet_lost,
	.on_path_change	= __bpf_tquic_sched_on_path_change,
	.set_param	= __bpf_tquic_sched_set_param,
	.get_stats	= __bpf_tquic_sched_get_stats,
};

/*
 * BPF struct_ops definition for TQUIC schedulers
 */
static struct bpf_struct_ops bpf_tquic_sched_ops = {
	.verifier_ops	= &bpf_tquic_sched_verifier_ops,
	.reg		= bpf_tquic_sched_reg,
	.unreg		= bpf_tquic_sched_unreg,
	.init_member	= bpf_tquic_sched_init_member,
	.init		= bpf_tquic_sched_init,
	.validate	= bpf_tquic_sched_validate,
	.name		= "tquic_scheduler_ops",
	.cfi_stubs	= &__bpf_ops_tquic_scheduler_ops,
	.owner		= THIS_MODULE,
};

/*
 * Module initialization
 */
static int __init bpf_tquic_sched_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&bpf_tquic_sched_kfunc_set);
	if (ret)
		return ret;

	ret = register_bpf_struct_ops(&bpf_tquic_sched_ops, tquic_scheduler_ops);
	if (ret) {
		pr_err("TQUIC: Failed to register BPF struct_ops: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC: BPF scheduler struct_ops registered\n");
	return 0;
}
late_initcall(bpf_tquic_sched_kfunc_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC BPF struct_ops for pluggable path schedulers");
