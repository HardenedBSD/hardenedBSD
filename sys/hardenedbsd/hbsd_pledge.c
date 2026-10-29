#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_pledge.h"

#ifdef HBSD_PLEDGE

/* TOOD determine overlap with man 9 priv,
   which defaults to checking euid/jail status when determining
  allowed privileges
  a good place to patch in overlapping things would
  probably be priv_check()/priv_check_cred()
*/

#include <sys/endian.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/pledge.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/tree.h>
#include <sys/counter.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <machine/atomic.h>
//#include <security/mac/mac_policy.h> // TODO this requires some additional includes for module_t etc
#include <sys/jail.h>
#include <sys/osd.h>

FEATURE(hbsd_hardening, "Pledge sandbox mechanism");

SDT_PROVIDER_DECLARE(pledge);
SDT_PROVIDER_DEFINE(pledge);


/* DTrace probe for recording privilege transitions (drops).
   pid, 0, 0, td->td_pledge, requested_mask.
   The zeroes are placeholders for fsid/inode, which unfortunately are expensive to obtain.
   TODO consider thread generation or similar identifying information,
   alternatively we could trace the vnode pointer to the executable, which
   could then be paired with a DTrace probe on process creation to obtain
   the path of the executable.
*/
SDT_PROBE_DEFINE5(pledge, kern, kern_pledge, masks,
    "pid_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");

/*
 * TODO dwatch tooling
 * DTrace SDT probe for recording violations of the pledge mask.
 * This provides a live view of the data available through the
 * security.pledge.learning_data sysctl.
 * reference: man 9 SDT
 * The arguments are (in this order):
 * - pid
 * - syscall number
 * - the current pledge mask possessed by thread
 * - the violated mask.
 * - the used mask
 * - TODO we should add additional fields like zfs txgid
 */
SDT_PROBE_DEFINE5(pledge, learning, insert, masks,
    "pid_t", "int", "uint64_t", "uint64_t", "uint64_t");

/*
 * Global exported symbols
 */

bool pledge_learning = 0;
bool pledge_enforcing = 0; /* TODO: = HBSD_PLEDGE; */


/*
 * Forward declarations for static functions and variables in this file:
 */

static int sysctl_pledge_flags(SYSCTL_HANDLER_ARGS);
static int sysctl_pledge_exec_flags(SYSCTL_HANDLER_ARGS);
static int sysctl_pledge_learning_data(SYSCTL_HANDLER_ARGS);
static bool pledge_is_modifier(uint64_t);
static int pledge_flags_to_string(uint64_t, char*, int);

static unsigned int pledge_jail_osd_slot;
static int pledge_jail_osd_create(void *_obj, void *_data);
static int pledge_jail_osd_remove(void *_obj, void *_data);

static void pledge_learning_init(const void *_unused);
static void pledge_learning_record(const struct thread *,
    const uint64_t, const uint64_t);

static PLEDGE_LEARNING_COMPARE_PROTOTYPE

/* see pledge.h for:
 * - splay element type learning_splay_t
 */

/* comparison function */
static PLEDGE_LEARNING_COMPARE_IMPL

/*
 * DPCPU(9)-sized array of tree root structs
 * TODO should we have __aligned(CACHE_LINE_SIZE) on RB_HEAD here and in the splay_entries array?
 */
typedef RB_HEAD(learning_tree, pledge_splay_t) learning_tree_t;
DPCPU_DEFINE_STATIC(learning_tree_t, learning_tree);

/*
 * Lock controlling insertion (write) and foreach/find (read) access to
 * the learning_tree array:
 */
DPCPU_DEFINE_STATIC(struct rmlock, learning_rm_lock);

RB_PROTOTYPE_STATIC(learning_tree,
    pledge_splay_t, tree_link, learning_tree_compare);

RB_GENERATE_STATIC(learning_tree,
    pledge_splay_t, tree_link, learning_tree_compare);


/* Initialize the learning mode structure before SI_SUB_CREATE_INIT
 * so we are ready for the first /sbin/init process:
 */

SYSINIT(pledge_sysinit_learning, SI_SUB_AUDIT, SI_ORDER_ANY,
    pledge_learning_init, NULL);


/*
 * sysctl declarations for security.pledge.*:
 * security.pledge.learning - toggle learning mode
 * security.pledge.learning_data - retrieve learning data
 * security.pledge.violations - violation counter
 * security.pledge.kills - counter of killed processes
 * security.pledge.softfails - counter of softfailed syscalls
 * security.pledge.enforcing - toggle enforcing mode
 * security.pledge.flags - get/set thread pledge bitmap
 */

SYSCTL_NODE(_security, OID_AUTO, pledge, 0, 0,
    "pledge policy controls");

SYSCTL_NODE(_security_pledge, OID_AUTO, jail, 0, 0,
    "jail-specific pledge policy controls");

SYSCTL_BOOL(_security_pledge, OID_AUTO, learning,
    CTLFLAG_ROOTONLY | CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_RWTUN,
    &pledge_learning, 0,
    "record pledge violations (0: off, 1: learning)");

SYSCTL_PROC(_security_pledge, OID_AUTO, learning_data,
    CTLFLAG_ROOTONLY | CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, 0, /* TODO args ??? */
    sysctl_pledge_learning_data, "S,pledge_learning_entry_t",
    "Retrieve the learning data entries");

static counter_u64_t learning_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, learning_count,
    CTLFLAG_ROOTONLY | CTLFLAG_RD | CTLFLAG_STATS,
    &learning_count, "Amount of recorded learning entries (for all CPUs)");

static counter_u64_t violation_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, violations,
    CTLFLAG_ROOTONLY | CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_STATS,
    &violation_count, "# of policy violations (enforced+learning)");

static counter_u64_t kill_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, kills,
    CTLFLAG_ROOTONLY | CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_STATS,
    &kill_count, "# of policy violations resulting in process kill");

static counter_u64_t softfail_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, softfails,
    CTLFLAG_ROOTONLY | CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_STATS,
    &softfail_count, "# of policy violations resulting in soft-fail");

/* TODO are proc nodes with CTLFLAG_SECURE generally accessible to
 * all users in the system? */
SYSCTL_BOOL(_security_pledge, OID_AUTO, enforcing,
  CTLFLAG_ROOTONLY | CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_RWTUN,
    &pledge_enforcing, 0,
    "enforce pledge violations (0: off, 1: enforcing)");

SYSCTL_PROC(_security_pledge, OID_AUTO, flags,
		CTLFLAG_PLEDGE | CTLTYPE_U64 | CTLFLAG_RW | CTLFLAG_ANYBODY
    | CTLFLAG_PRISON | CTLFLAG_CAPWR | CTLFLAG_CAPRD | CTLFLAG_MPSAFE,
    NULL, 0, /* arg1, arg2 */
    sysctl_pledge_flags, "S,uint64_t", /* function, format*/
    "Reduce pledge flags for the calling thread and return previous flags.");

SYSCTL_PROC(_security_pledge, OID_AUTO, exec_flags,
		CTLFLAG_PLEDGE | CTLTYPE_U64 | CTLFLAG_RW | CTLFLAG_ANYBODY
		| CTLFLAG_PRISON | CTLFLAG_CAPWR | CTLFLAG_CAPRD | CTLFLAG_MPSAFE,
		NULL, 0,
		sysctl_pledge_exec_flags, "S,uint64_t",
		"Set exec-time pledge flags for the calling thread.");

SYSCTL_NODE(_security_pledge, OID_AUTO, override, 0, 0,
    "Override required flags for a given syscall.");

/*
 * sysctl proc node for applying a new pledge mask to the calling thread.
 * The supplied mask is AND'ed with the thread's current mask, permitting
 * only reductions.
 */
static int
sysctl_pledge_flags(SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	uint64_t new_flags = req->td->td_pledge;

	error = sysctl_handle_64(oidp, &new_flags, 0, req);

	if (!error && req->newptr) {
		kern_pledge(req->td, new_flags);
	}

	return error;
}

static int
sysctl_pledge_exec_flags(SYSCTL_HANDLER_ARGS)
{
		int error = 0;
		uint64_t new_flags = req->td->td_pledge_exec;

		error = sysctl_handle_64(oidp, &new_flags, 0, req);

		if (!error && req->newptr) {
			kern_pledge_exec(req->td, new_flags);
		}

		return error;
}

static int
pledge_jail_osd_create(void *obj, void *data __unused)
{
	struct prison *pr = obj;
	//struct vfsoptlist *vfsopts = (struct vfsoptlist *)data;
	struct pledge_jail_data *pjd = NULL;

	/* vfsopts contains jail options in case we want to do
	 * something with those. TODO. */

	/*
	 * TODO we could walk
	 * while ((parent = pr->pr_parent)) {
	 *   inherit from parent
	 * }
	 */

	pjd = malloc(sizeof(struct pledge_jail_data), M_PRISON, M_ZERO|M_WAITOK);
	pjd->is_enforcing = pledge_enforcing; /* inherit from global */
	pjd->violations = counter_u64_alloc(M_WAITOK);

	sysctl_ctx_init(&pjd->sysctl_ctx);

	char jail_id_str[16] = {0};
	snprintf(jail_id_str, sizeof(jail_id_str), "%u", pr->pr_id);
	/* add under security.pledge: */
	struct sysctl_oid *oidp = SYSCTL_ADD_NODE(&pjd->sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_security_pledge_jail),
	    OID_AUTO,
	    jail_id_str, CTLFLAG_RW, NULL, "controls for this jid");
	/* add under oidp */
	SYSCTL_ADD_BOOL(&pjd->sysctl_ctx, SYSCTL_CHILDREN(oidp), OID_AUTO,
	    "enforcing", CTLFLAG_RW, &pjd->is_enforcing, 0,
	    "enforcing for this jail");
	SYSCTL_ADD_COUNTER_U64(&pjd->sysctl_ctx, SYSCTL_CHILDREN(oidp),
	    OID_AUTO,
	    "violations", CTLFLAG_RW, &pjd->violations,
	    "violation count for this jail");

	void **rsv = osd_reserve(pledge_jail_osd_slot);
	for (int retry = 1; retry;)
	{
		prison_lock(pr);
		retry = osd_jail_set_reserved(pr,
		    pledge_jail_osd_slot, rsv, pjd);
		prison_unlock(pr);
	}

	return 0;
}

static int
pledge_jail_osd_remove(void *obj, void *data __unused)
{
	struct prison *pr = obj;
	//struct vfsoptlist *vfsopts = data;

	prison_lock(pr);
	struct pledge_jail_data *pjd = osd_jail_get(pr, pledge_jail_osd_slot);
	prison_unlock(pr);

	if (NULL == pjd) {
		printf("pledge_jail_remove: pjd == NULL (pr == prison0: %d)\n",
		    (pr == &prison0));
		return 0; /* TODO shouldn't happen? */
	}

	/* Cleanup sysctls: */
	sysctl_ctx_free(&pjd->sysctl_ctx);
	counter_u64_free(pjd->violations);
	free(pjd, M_PRISON);

	return 0;
}

/*
 * Learning mode
 * pledge_learning_init() - allocate table
 * pledge_learning_hash() - hash (fsid,inode) tuple to int
 * pledge_learning_insert() - update entry with used/violated flags
 * pledge_learning_record() - find (fsid,inode) and insert if learning enabled
 */

static MALLOC_DEFINE(M_PLEDGE_LEARNING, "pledge learning data",
    "pledge(8) learning mode data points.");

/*
 * Initialize learning mode memory structures
 */
static void
pledge_learning_init(const void *_unused)
{
	violation_count = counter_u64_alloc(M_WAITOK);
	learning_count = counter_u64_alloc(M_WAITOK);
	kill_count = counter_u64_alloc(M_WAITOK);
	softfail_count = counter_u64_alloc(M_WAITOK);

	/*
	 * These are small; we INIT them regardless of learning==1
	 * to avoid the headache of having to check for initialization later on:
	 */
	u_int cpu = 0;
	CPU_FOREACH(cpu) {
		rm_init(DPCPU_ID_PTR(cpu, learning_rm_lock),
			"security.pledge.learning");
		RB_INIT(DPCPU_ID_PTR(cpu, learning_tree));
	}

	/* TODO add a tunable for each system call.
	 * This should modify the pledge_permission_map to allow overriding
	 * the pledge permission mask for syscalls to enable troubleshooting
	 * when new syscalls are added without having to recompile the kernel.
	struct sysctl_oid *mynode = SYSCTL_ADD_U64(_security_pledge_override,
	    TODOTODO  CTLFLAG_RWTUN | CTLFLAG_SECURE | CTLFLAG_RD
		);
	*/

	/*
	 * Install per-jail osd.h hooks.
	 * The PR_* constants are from jail.h
	 */
	osd_method_t osdmethods[PR_MAXMETHOD] = {NULL};
	osdmethods[PR_METHOD_CREATE] = pledge_jail_osd_create;
	osdmethods[PR_METHOD_REMOVE] = pledge_jail_osd_remove;

	/*
	 * Go through existing jails, taking the allprison_lock before
	 * registering our slot to ensure we don't trigger two calls
	 * to pledge_jail_osd_create for any given jail (one from osd,
	 * and one here).
	 * That might be overly careful, not sure how realistic jails
	 * being spawned at this point is.
	 */
	sx_slock(&allprison_lock);
	pledge_jail_osd_slot = osd_jail_register(NULL, osdmethods);
	struct prison *pr = &prison0;
	(void)pledge_jail_osd_create(pr, NULL);
	TAILQ_FOREACH(pr, &allprison, pr_list) {
		(void)pledge_jail_osd_create(pr, NULL);
	}
	sx_sunlock(&allprison_lock);
}

/*
 * Erase learning entries.
 * Returns the number of bytes the erased entries would have required to dump
 * to userspace, in multiples of sizeof(pledge_learning_entry_t).
 */
size_t
kern_pledge_learning_data_erase(void)
{
	size_t erased_bytes = 0;
	u_int cpu = 0;
	CPU_FOREACH(cpu) {
		struct rmlock * const rm = DPCPU_ID_PTR(cpu, learning_rm_lock);
		rm_wlock(rm);
		learning_tree_t * const tree = DPCPU_ID_PTR(cpu, learning_tree);
		pledge_splay_t *el = NULL, *el_tmp = NULL;
		RB_FOREACH_SAFE(el, learning_tree, tree, el_tmp) {
			learning_tree_RB_REMOVE(tree, el);
			free(el, M_PLEDGE_LEARNING);
			erased_bytes += sizeof(pledge_learning_entry_t);
		}
		rm_wunlock(rm);
	}
	return erased_bytes;
}

/*
 * Records the utilized and violated pledge privileges for a given executable
 * as identified by (fsid,inode) tuple.
 */
static inline void
pledge_learning_insert(const struct thread*thread,
    const dev_t fsid, const ino_t inode,
    const uint64_t used_mask, const uint64_t violated_mask){

	SDT_PROBE5(pledge, learning, insert, masks,
	   thread->td_proc->p_pid, thread->td_sa.code,
	    thread->td_pledge, violated_mask, used_mask);

	/* Skip if learning mode is disabled: */
	if (!pledge_learning)
		return;

	u_int tree_idx = curcpu;
	struct rmlock * const rm = DPCPU_ID_PTR(tree_idx, learning_rm_lock);
	struct rm_priotracker rm_tracker = { 0 };
	rm_rlock(rm, &rm_tracker);
	learning_tree_t *tree = DPCPU_ID_PTR(tree_idx, learning_tree);

	/* Allocate member on the stack used to find existing entry
	 * with this inode/fsid combination. If there isn't one,
	 * we will need to copy this data to a proper allocation
	 * before inserting.
	 */
	pledge_splay_t stack_el = {
		.inode = inode,
		.fs_id = fsid,
		/* zero-initialize the remaining members
		 * since we may later want to add it to the tree */
		0
	};

	/* check if we already have an entry */
	pledge_splay_t *el =
	    learning_tree_RB_FIND(tree, &stack_el);

	if (el) {
		el->used |= used_mask;
		el->violated |= violated_mask;
		el->possessed |= thread->td_pledge;

		rm_runlock(rm, &rm_tracker);

		return;
	}

	/* the executable did not already have an entry,
	   so we need to add one. */

	/* drop lock so we can malloc our new entry: */
	rm_runlock(rm, &rm_tracker);
	/* would it make sense to use malloc_domainset here? */
	el = malloc(sizeof(stack_el),
	    M_PLEDGE_LEARNING, M_WAITOK | M_ZERO);
	memcpy(el, &stack_el, sizeof(stack_el));

	rm_wlock(rm);

	pledge_splay_t * const inserted = learning_tree_RB_INSERT(tree, el);
	if (__builtin_expect((long)inserted, false)) {
		/* while we were busy malloc'ing,
		 * we were preempted, and the same
		 * element was inserted into this tree.
		 * use that instead of the newly malloc'ed entry that did not
		 * make it into the tree:
		 */
		free(el, M_PLEDGE_LEARNING);
		el = inserted;
	} else {
		counter_u64_add(learning_count, 1);
	}

	el->used |= used_mask;
	el->violated |= violated_mask;
	el->possessed |= thread->td_pledge;

	rm_wunlock(rm);
}

/*
 * TODO. ideally we would not call VOP_GETATTR on *each* call to this...
 */
static inline void
pledge_learning_record(const struct thread *thread,
    const uint64_t used_mask,
    const uint64_t violated_mask)
{
	if (!pledge_learning) { /* check sysctl */
		return;
	}

	int err = 0;

	/* seems like this would be a great place to have a LRU cache
	   of vnode/inode to avoid having to take all these locks...*/

	/* pointer to vnode for thread's executable */
	/* locks: thread->td_proc (*) not yet protected
	 * td_proc->p_textvp (b) created at fork, never changes
	 */
	PROC_LOCK(thread->td_proc);
	struct vnode * const exec_vnode = thread->td_proc->p_textvp;
	PROC_UNLOCK(thread->td_proc);

	/* assert that we have a vnode, and that it is a regular file: */
	if (!exec_vnode || VREG != exec_vnode->v_type) {
		/* in this case should probably have an ERROR entry
		 * that contains the appropriate mask for things we
		 * failed to look up? */
	  printf("pledge not exec_vnode OR not vreg TODO\n");
		goto proc_unlock_and_return;
	}

	struct vattr exec_vattr = {0};
	err = VOP_GETATTR(exec_vnode, &exec_vattr, NOCRED);
	if (__builtin_expect(err, 0)) {
	  printf("pledge VOP_GETATTR failed, locked:%d\n", VOP_ISLOCKED(exec_vnode));
		goto proc_unlock_and_return;
	}

	const dev_t exec_fsid = exec_vattr.va_fsid;
	const ino_t exec_fileid = exec_vattr.va_fileid;
	_Static_assert(sizeof(exec_vattr.va_fileid) == sizeof(ino_t), "va_fileid<>ino_t");
	/* TODO consider grouping by exec_vattr.va_filerev also?
	 * for ZFS that seems like it contains txgid ?
	 * https://github.com/freebsd/freebsd/blob/45d716be60e3806a85a0822cec12b8ce2321003b/sys/cddl/contrib/opensolaris/uts/common/fs/zfs/zfs_vnops.c#L2668
	 * Alternatively we could do something like track modification time
	 * and clear the recorded flags upon modification (or just store
	 * duplicate entries where userland will have to decide with outdated
	 * recordings. Finally we could let that be up to the user through
	 * sysctl configuration. )
	 */

	pledge_learning_insert(thread, exec_fsid, exec_fileid,
	    used_mask, violated_mask);

	goto proc_unlock_and_return;


	printf("pledge TODO proc_unlock_and_return: not good.\n");
proc_unlock_and_return:
	//PROC_UNLOCK(thread->td_proc);
	return;
}

/*
 * sysctl proc node that copies (to userspace) the learning data.
 * newptr newlen oldptr oldlen  outcome
 *      *     !0      *      *  EINVAL, reserved
 *  !NULL      0  !NULL      *  EINVAL, reserved
 *  !NULL      0   NULL      *  Erase learning data
 *   NULL      0  !NULL      *  Put learning data in oldptr (up to oldlen bytes)
 *   NULL      0   NULL      *  Retrieve bufsize required for learning entries
 */
static int
sysctl_pledge_learning_data(SYSCTL_HANDLER_ARGS)
{
	/* TODO it's unfortunate that only sum(dpcpu counter array) is exposed;
	 * being able to retrieve max(dpcpu counter array) would be useful. */
	const uint64_t entries_num_max = counter_u64_fetch(learning_count);
	uint64_t entries_bytes_max =
	    entries_num_max * sizeof(pledge_learning_entry_t);

	if (req->newlen) {
		/* rew->newlen is reserved for now. */
		printf("pledge: trying to set learning data,"
		    " not implemented.\n");
		return EINVAL;
	}

	if (NULL == req->oldptr) {
		if (NULL != req->newptr) {
			entries_bytes_max = kern_pledge_learning_data_erase();
		}
		/* if userspace provided req->newptr, we returned the space
		 * required by the erased entries.
		 * Otherwise, userspace did not provide a place to put entries;
		 * and is only interested in space required to dump data.
		 */
		return SYSCTL_OUT(req, NULL, entries_bytes_max);
	}

	if (req->newptr) {
		printf("sysctl_pledge_learning_data: newptr && oldptr\n");
		return EINVAL;
	}

	const size_t idx_max = req->oldlen / sizeof(pledge_learning_entry_t);

	if (idx_max * sizeof(pledge_learning_entry_t) != req->oldlen) {
		/* userland should ask for at least one entry and give
		 * us exactly the space we need to store them: */
		printf("pledge: learning_data %zd EINVAL TODO\n", req->oldlen);
		return (EINVAL);
	}

	/* Allocate contiguous buffer so we can attempt one big copyout().
	 * User can potentially request a very large amount of memory, so we
	 * allow the malloc to fail.
	 * One big buffer seemed better than doing copyouts for each element,
	 * but it scales poorly with a large number of CPUs.
	 * Could also consider a copyout per CPU node, or to merge the data in-kernel.
	 * TODO also consider returning EINVAL if
	 * req->oldlen > entries_num_max + (n) * mp_ncpus
	 * where (n) is some sensible constant (since we don't have a
	 * synced upper bound to compare against).
	 * It seemed unclean, so I did not include that here. */
	pledge_learning_entry_t * const entry_arr =
	    malloc(req->oldlen, M_PLEDGE_LEARNING, M_ZERO | M_WAITOK);

	size_t idx = 0;
	int err = 0;

	u_int cpu = 0;
	CPU_FOREACH(cpu) {
		if (idx >= idx_max) break;
		struct rmlock * const rm = DPCPU_ID_PTR(cpu, learning_rm_lock);
		struct rm_priotracker rm_tracker = { 0 };
		rm_rlock(rm, &rm_tracker);
		learning_tree_t * const tree = DPCPU_ID_PTR(cpu, learning_tree);
		pledge_splay_t *el = NULL;
		RB_FOREACH(el, learning_tree, tree) {
			if (idx >= idx_max) break;
			/* printf("pledge el: inode %lu fs_id: %lu"
			    " used:0x%0lx viol:0x%0lx pos:0x%0lx\n",
			    el->inode, el->fs_id,
			    el->used, el->violated, el->possessed); */
			pledge_learning_entry_t * const user_entry =
			    entry_arr + idx;
			user_entry->is_populated = true;
			user_entry->used_flags = el->used;
			user_entry->violated_flags = el->violated;
			user_entry->possessed = el->possessed;
			user_entry->inode = el->inode;
			user_entry->fsid = el->fs_id;
			idx++;
		}
		rm_runlock(rm, &rm_tracker);
	}

	err = SYSCTL_OUT(req, entry_arr, idx*sizeof(pledge_learning_entry_t));
	if (err) {
		printf("pledge:SYSCTL_OUT failed err %d idx %zd\n", err, idx);
	}

	free(entry_arr, M_PLEDGE_LEARNING);

	return (err);
}


/*
 * Generic function to handle a permission check.
 * By default it checks if ONE of the flags is set, this behaviour can be
 * changed to compare against all the flags by OR'ing with PLEDGE_AND.
 * Returns ENOTCAPABLE or exits() the process, this function MAY NOT RETURN.
 */
int
pledge_check_bitmap(struct thread * const thread, const uint64_t flags)
{

	/* Assume we need to match ALL the flags: */
	uint64_t violated =
	    (flags & PLEDGE_WILDCARD)
	    & (~(thread->td_pledge));

	/* used_mask is the intersection between required and possessed: */
	// TODO atm we over-report a little bit since if AND is not set
	// we really only need one of them, not all of the target flags.
	// Potential solution would be to just pick the lowest.
	uint64_t used_mask =
	    (flags & PLEDGE_WILDCARD & thread->td_pledge);

	/* Retain (violated) if one or more constraints are met:
	 * 1) the PLEDGE_AND bit is set in (flags)
	 * 2) the permission intersection of (flags) and (td_pledge) is empty
	 * Conversely this clears (violated) by multiplying it with 0
	 * when !PLEDGE_AND && at least one required permission is possessed.
	 */
	violated *=
	    !!( (PLEDGE_AND & flags)
		| !used_mask);

	/* Record the lacking permissions unless there is no violation
	 * and PLEDGE_NOLEARN was supplied in (flags).
	 * TODO document this in the manpages
	 * TODO document in pledgectl
	 */
	if (violated || !(PLEDGE_NOLEARN & flags)) {
		pledge_learning_record(thread, used_mask, violated);
	}

	if (violated & PLEDGE_WILDCARD)
		counter_u64_add(violation_count, 1);

	if (violated) {
		/* Consult the jail-specific entry.*/
		/* TODO: is (thread) always (curthread) here? */
		struct prison *pr = thread->td_ucred->cr_prison;
		prison_lock(pr);
		struct pledge_jail_data *pjd = osd_jail_get(pr,
		    pledge_jail_osd_slot);
		if (pjd) {
			if (violated) {
				counter_u64_add(pjd->violations, 1);
			}
			if ( !(pledge_enforcing || pjd->is_enforcing) ) {
				violated = 0;
			}
		} else {
			// TODO just assert that pjd != NULL
			counter_u64_add(softfail_count, 10);
		}
		prison_unlock(pr);
	}

	if (violated) {
		/* return a permission error if the wanted syscall_no is not
		 * permitted by the thread's current pledge bitmap: */

		char pname[1024] = {0};
		if(pledge_flags_to_string(violated, &pname[0], 1024))
			strcpy(&pname[0], "unknown");

		tprintf(
			thread->td_proc, 0,
			"%s[%d] pledge \"%s\", syscall %d (\"%s\")\n",
			thread->td_proc->p_comm,
			thread->td_proc->p_pid,
			pname,
			thread->td_sa.code,
			syscallname(thread->td_proc, thread->td_sa.code)
		);

		if (0 == (thread->td_pledge & PLEDGE_SOFTFAIL)) {
			/* crash process:
			 * 2nd arg is exit code
			 * 3rd arg is signo
			 * TODO maybe call sys_abort2 instead to produce
			 * inspectable core? */
			counter_u64_add(kill_count, 1);
			exit1(thread, 0, SIGKILL);
			// TODO misunderstood exit1?
			counter_u64_add(kill_count, 1337);
		}

		counter_u64_add(softfail_count, 1);
		return (ENOTCAPABLE);
	}

	return 0;
}

static
int pledge_flags_to_string(uint64_t flags, char *buf, int size) {
	int error;
	error = 0;

	if (buf == NULL)
		goto err;
	buf[0] = '\0';

	for (size_t i = 0; i < nitems(pledge_string_map); i++) {
		const typeof(pledge_string_map[0]) *pledge;
		pledge = &pledge_string_map[i];
		if (flags & pledge->constant) {
			if (pledge_is_modifier(pledge->constant))
				continue;
			size_t len;
			len = strlen(buf);
			if (len && len + 2 < size)
				strcat(buf, " ");
			len = strlen(buf);
			if (len + strlen(pledge->name) + 1 < size) {
				strcat(buf, pledge->name);
			}
		}
	}
	return error;

err:
	error = 1;
	return error;
}

static
bool pledge_is_modifier(uint64_t pledge) {
	switch(pledge) {
		case PLEDGE_AND:
		case PLEDGE_WILDCARD:
		case PLEDGE_NONE:
		case PLEDGE_NOLEARN:
		case PLEDGE_SOFTFAIL:
		case PLEDGE_INHERIT:
			return (true);
		default:
			return (false);
	}
}

int
pledge_sysctl_check(struct thread *thread, struct sysctl_oid *oid) {
	/* allow: thread carries a wildcard */
	if (thread->td_pledge == PLEDGE_WILDCARD) {
		return (0);
	}

	/* allow: thread carries PLEDGE_SYSCTL */
	if (thread->td_pledge & PLEDGE_SYSCTL) {
		return (0);
	}

	/* allow: oid carries CTLFLAG_PLEDGE */
	if (oid->oid_kind & CTLFLAG_PLEDGE) {
		return (0);
	}

	/* deny: if we get here, let pledge_check_bitmap
	         handle failure. It might crash the program,
		    or softfail by setting errno to ENOTCAPABLE.
	*/
	return (pledge_check_bitmap(thread, PLEDGE_SYSCTL));
}

/*
 * Apply intersection of new permission mask and the current mask.
 * Always succeeds.
 */
int
kern_pledge(struct thread *td, const uint64_t mask)
{
	/* Would probably be a good place for a DTrace probe.*/
	/* TODO do we need to lock td? */
	SDT_PROBE5(pledge, kern, kern_pledge, masks,
	    td->td_proc->p_pid, 0, 0, td->td_pledge, mask);
	td->td_pledge &= (mask & ~PLEDGE_AND);
	return 0;
}

int
kern_pledge_exec(struct thread *td, const uint64_t execmask)
{
	td->td_pledge_exec &= (execmask & ~PLEDGE_AND);
	return 0;
}

/*
 * Look up pledge bitmask for binary stored in the
 * "system:pledge" and "user:pledge" extattrs,
 * applying the associated masks (if they exist) to the
 * thread's current pledge mask.
 * The bitmasks are always stored in little-endian byte order.
 * Returns 0 on success (including if the extattrs do not exist),
 * and nonzero on error.
 */
int
pledge_apply_extattr(struct thread *td, struct vnode *ni_vp)
{
	int err = 0;

	uint64_t retrieved_mask = PLEDGE_NONE;

	for (int namespace = 0; namespace < 2; ++namespace) {
		struct uio uio = {0};
		struct iovec iov = {0};

		/*
		 * Read the system:pledge extattr on the file in question.
		 */

		iov.iov_base = &retrieved_mask;
		iov.iov_len = sizeof(retrieved_mask);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_rw = UIO_READ;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_td = td;
		uio.uio_resid = sizeof(retrieved_mask);

		err = VOP_GETEXTATTR(ni_vp,
		    (namespace == 0
			? EXTATTR_NAMESPACE_SYSTEM
			: EXTATTR_NAMESPACE_USER),
		    "pledge",
		    &uio, NULL, NOCRED, td);

		// uio.uio_resid holds "remaining" counter, this should drop to 0 once read?


		/* TODO maybe this should be EXTATTR_NAMESPACE_USER to permit
		   people to pledge their own binaries */

		/* TODO I guess we need to bypass read permissions iff (td->ucred) has
		 * execute permission to the binary seeing as execution has gotten
		 * this far, we assume this is the case.
		 * Using td->td_ucred resulted in EPERM errors.
		 * Need to evaluate NOCRED vs td->td_ucred, also in other VOP_ ops
		 * in hbsd_pledge.c
		 */

		if (ENOATTR == err || EOPNOTSUPP == err) {
			/* it doesn't have a "pledge" extattr: */
			continue;
		} else if (err) {
			printf("pledge_getmask_extattr: VOP_GETEXTATTR on  vnode %p "
			    "for attribute system:'pledge' failed with error (%d)\n",
			    ni_vp, err);
			return 1;
		} else if (0 == uio.uio_resid) {
			/*
			 * TODO excellent place for a DTrace probe
			 */
			printf("pledge_getmask_extattr: vnode %p pledgemask 0x%lx\n",
			    ni_vp, retrieved_mask);
			retrieved_mask = le64toh(retrieved_mask);
			int err = kern_pledge(td, retrieved_mask);
			if (err) return err;
		}
		else {
			/*
			 * If there's more data in here, something is wrong.
			 */
			tprintf(td->td_proc, 0, "pledge_getmask_extattr: "
			    "size of system.pledge extattr is %zd, expected == %zd\n",
			    uio.uio_resid, sizeof(retrieved_mask));
			return 1;
		}
	}
	return 0;
}

/*
 * Validate open() access.
 * May not return, so care should be taken to free structures prior to calling.
 */
int inline
pledge_openat(struct thread *thread, const int fd, const char *path,
    const int flags, const int mode)
{

	uint64_t required_mask = PLEDGE_AND | PLEDGE_RPATH | PLEDGE_WPATH
	    | PLEDGE_CPATH | PLEDGE_FLOCK;

	/* TODO this would probably be a good point for path validation
	 * and whitelisting of /dev/null, /dev/urandom, etc.
	 * it would however feel better to check major/minor dev number
	 * to avoid problems with symlinks and whathaveyou.
	 */

	/* determine required capabilities depending on the open() flags:*/

	if (0 == (FFLAGS(flags) & FREAD))
		required_mask ^= PLEDGE_RPATH;

	if (0 == (FFLAGS(flags) & (FWRITE | FAPPEND)))
		required_mask ^= PLEDGE_WPATH;

	if (0 == (flags & O_CREAT)) {
		required_mask ^= PLEDGE_CPATH;
	}

	if (0 == (flags & (O_SHLOCK | O_EXLOCK)))
		required_mask ^= PLEDGE_FLOCK;

	if (PLEDGE_WILDCARD != (PLEDGE_WILDCARD & thread->td_pledge)) {
		/* TODO consider DTrace probe
		   printf("pledge: openat: flags:0x%0x vs req:0x%0lx\n",
		    flags, required_mask);
		*/
	}

	return (pledge_check_bitmap(thread, required_mask));
}

/*
 * This map is used in pledge_syscall() to determine which pledge flags are
 * relevant to determine access to a given syscall.
 * The syscall is allowed if ONE OR MORE flags match the thread's bitmap.
 *
 * The syscalls we do not filter using pledge are permitted by
 * initializing the entry in this table to PLEDGE_WILDCARD.
 *
 * The rationale for listing all of the system calls here is the philosophy
 * that even though it requires more maintenance, it is better to deny an
 * attempt to call an unhandled system call than permitting it.
 *
 * NOTE that there is a special case in that function that grants access if
 * pledge is turned off for that thread (when it is PLEDGE_WILDCARD), which is
 * the default defined in sys/kern/init_main.c
 *
 * These are listed in numerical, ascending order (see sys/sys/syscalls.h):
 */
static
uint64_t pledge_permission_map[SYS_MAXSYSCALL] = {
	/* 0: */
	[SYS_syscall]	= PLEDGE_AND | PLEDGE_WILDCARD, /* requires unpledged process */
	[SYS_exit]	= PLEDGE_NONE,
	[SYS_fork]	= PLEDGE_PROC,
	[SYS_read]	= PLEDGE_NONE,
	[SYS_write]	= PLEDGE_NONE,
	[SYS_open]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH | PLEDGE_NOLEARN, /* NOLEARN: handled in pledge_openat */
	[SYS_close]	= PLEDGE_STDIO,
	[SYS_wait4]	= PLEDGE_PROC,
	[SYS_link]	= PLEDGE_CPATH,
	/* 10: */
	[SYS_unlink]	= PLEDGE_CPATH,
	[SYS_chdir]	= PLEDGE_STDIO,
	[SYS_fchdir]	= PLEDGE_STDIO,
#ifdef SYS_freebsd11_mknod
	[SYS_freebsd11_mknod]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#else
	[SYS_mknod]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#endif
	[SYS_chmod]	= PLEDGE_FATTR,
	[SYS_chown]	= PLEDGE_CHOWN,
	[SYS_break]	= PLEDGE_STDIO,
	/* 20: */
	[SYS_getpid]	= PLEDGE_NONE,
	[SYS_mount]	= PLEDGE_DEVICE,
	[SYS_unmount]	= PLEDGE_DEVICE,
	[SYS_setuid]	= PLEDGE_ID,
	[SYS_getuid]	= PLEDGE_NONE,
	[SYS_geteuid]	= PLEDGE_NONE,
	[SYS_ptrace]	= PLEDGE_PROC,
	[SYS_recvmsg]	= PLEDGE_STDIO,
	[SYS_sendmsg]	= PLEDGE_STDIO,
	[SYS_recvfrom]	= PLEDGE_STDIO,
	/* 30: */
	[SYS_accept]	= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getpeername] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getsockname] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_access]	= PLEDGE_RPATH,
	[SYS_chflags]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS_fchflags]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS_sync]	= PLEDGE_STDIO,
	[SYS_kill]	= PLEDGE_PROC,
	[SYS_getppid]	= PLEDGE_STDIO,
	[SYS_dup]	= PLEDGE_STDIO,
	[SYS_freebsd10_pipe] = PLEDGE_STDIO,
	[SYS_getegid]	= PLEDGE_STDIO,
	[SYS_profil]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC, // TODO??
	[SYS_ktrace]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_PROC,
	[SYS_getgid]	= PLEDGE_NONE,
	[SYS_getlogin]	= PLEDGE_STDIO,
	/* 50: */
	[SYS_setlogin]	= PLEDGE_ID,
	[SYS_acct]	= PLEDGE_PROC,
	[SYS_sigaltstack] = PLEDGE_STDIO,
	[SYS_ioctl]	= PLEDGE_IOCTL,
	[SYS_reboot]	= PLEDGE_PROC,
	[SYS_revoke]	= PLEDGE_AND | PLEDGE_PROC | PLEDGE_RPATH,
	[SYS_symlink]	= PLEDGE_CPATH,
	[SYS_readlink]	= PLEDGE_RPATH,
	[SYS_execve]	= PLEDGE_EXEC,
	/* 60: */
	[SYS_umask]	= PLEDGE_STDIO,
	[SYS_chroot]	= PLEDGE_DEVICE,
	[SYS_msync]	= PLEDGE_STDIO,
	[SYS_vfork]	= PLEDGE_PROC,
#ifdef SYS_sbrk
	[SYS_sbrk]	= PLEDGE_STDIO,
#endif
#ifdef SYS_sstk
	/* 70: */
	[SYS_sstk]	= PLEDGE_STDIO,
#endif
#ifndef SYS_vadvise
#define SYS_vadvise SYS_freebsd11_vadvise
#endif
	[SYS_vadvise]	= PLEDGE_STDIO,
	[SYS_munmap]	= PLEDGE_STDIO,
	[SYS_mprotect]	= PLEDGE_STDIO,
	[SYS_madvise]	= PLEDGE_STDIO,
	[SYS_mincore]	= PLEDGE_STDIO,
	/* 80: */
	[SYS_getpgrp]		= PLEDGE_STDIO,
	[SYS_setpgid]		= PLEDGE_STDIO,
	[SYS_setitimer]	= PLEDGE_STDIO,
	[SYS_swapon]		= PLEDGE_DEVICE,
	[SYS_getitimer]	= PLEDGE_STDIO,
	[SYS_getdtablesize]	= PLEDGE_STDIO,
	/* 90: */
	[SYS_dup2]	= PLEDGE_STDIO,
	[SYS_fcntl]	= PLEDGE_STDIO,
	[SYS_select]	= PLEDGE_STDIO,
	[SYS_fsync]	= PLEDGE_STDIO,
	[SYS_setpriority] = PLEDGE_STDIO,
	[SYS_socket]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	[SYS_connect]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	/* 100: */
	[SYS_getpriority]	= PLEDGE_STDIO,
	[SYS_bind]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	[SYS_setsockopt]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX, // TODO
	[SYS_listen]	= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_gettimeofday]	= PLEDGE_NONE,
	[SYS_getrusage]	= PLEDGE_STDIO,
	[SYS_getsockopt]	= PLEDGE_INET | PLEDGE_UNIX,
	/* 120: */
	[SYS_readv]	= PLEDGE_STDIO,
	[SYS_writev]	= PLEDGE_STDIO,
	[SYS_settimeofday]	= PLEDGE_SETTIME,
	[SYS_fchown]	= PLEDGE_CHOWN,
	[SYS_fchmod]	= PLEDGE_FATTR,
	[SYS_setreuid]	= PLEDGE_ID,
	[SYS_setregid]	= PLEDGE_ID,
	[SYS_rename]	= PLEDGE_CPATH,
	[SYS_flock]	= PLEDGE_FLOCK,
	[SYS_mkfifo]	= PLEDGE_DPATH,
	[SYS_sendto]	= PLEDGE_STDIO,
	[SYS_shutdown]	= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_socketpair]	= PLEDGE_STDIO,
	[SYS_mkdir]	= PLEDGE_CPATH,
	[SYS_rmdir]	= PLEDGE_CPATH,
	[SYS_utimes]	= PLEDGE_FATTR,
	/* 140: */
	[SYS_adjtime]	= PLEDGE_SETTIME,
	[SYS_setsid]	= PLEDGE_STDIO,
	[SYS_quotactl]	= PLEDGE_DEVICE,
	[SYS_nlm_syscall] = PLEDGE_STDIO, /* TODO */
	[SYS_nfssvc]	= PLEDGE_STDIO,
	/* 160: */
	[SYS_lgetfh]	= PLEDGE_RPATH,
	[SYS_getfh]	= PLEDGE_RPATH,
	[SYS_sysarch]	= PLEDGE_STDIO, /* TODO */
	[SYS_rtprio]	= PLEDGE_STDIO,
	[SYS_semsys]	= PLEDGE_STDIO,
	/* 170: */
	[SYS_msgsys]	= PLEDGE_STDIO, /* TODO */
	[SYS_shmsys]	= PLEDGE_STDIO,
	[SYS_setfib]	= PLEDGE_ROUTE,
	[SYS_ntp_adjtime] = PLEDGE_SETTIME,
	[SYS_setgid]	= PLEDGE_ID,
	[SYS_setegid]	= PLEDGE_ID,
	[SYS_seteuid]	= PLEDGE_ID,
	[SYS_freebsd11_stat]	= PLEDGE_RPATH,
#ifdef SYS_freebsd11_fstat
	[SYS_freebsd11_fstat]	= PLEDGE_RPATH,
#endif
	/* 190: */
	[SYS_freebsd11_lstat]	= PLEDGE_RPATH,
	[SYS_pathconf]	= PLEDGE_STDIO, // NONE?
	[SYS_fpathconf] = PLEDGE_STDIO,
	/* TODO what happened to 193? */
	[SYS_getrlimit] = PLEDGE_STDIO,
	[SYS_setrlimit] = PLEDGE_STDIO,
	[SYS_freebsd11_getdirentries] = PLEDGE_RPATH,

	/* requires unpledged process */
	[SYS___syscall] = PLEDGE_AND | PLEDGE_WILDCARD,

	/* checked by kern_sysctl.c */
	[SYS___sysctl]	= PLEDGE_SYSCTL,

	[SYS_mlock]	= PLEDGE_STDIO,
	[SYS_munlock]	= PLEDGE_STDIO,
	[SYS_undelete]	= PLEDGE_CPATH, // TODO
	[SYS_futimes]	= PLEDGE_FATTR,
	[SYS_getpgid]	= PLEDGE_STDIO,
	[SYS_poll]	= PLEDGE_STDIO,
	/* 220: */
	[SYS_freebsd7___semctl] = PLEDGE_STDIO,
	[SYS_semget]	= PLEDGE_STDIO,
	[SYS_semop]	= PLEDGE_STDIO,
	[SYS_freebsd7_msgctl] = PLEDGE_STDIO,
	[SYS_msgget]	= PLEDGE_STDIO,
	[SYS_msgsnd]	= PLEDGE_STDIO,
	[SYS_msgrcv]	= PLEDGE_STDIO,
	[SYS_shmat]	= PLEDGE_STDIO,
	[SYS_freebsd7_shmctl]	= PLEDGE_STDIO,
	/* 230: */
	[SYS_shmdt]	= PLEDGE_STDIO, /* TODO */
	[SYS_shmget]	= PLEDGE_STDIO,
	[SYS_clock_gettime]	= PLEDGE_STDIO,
	[SYS_clock_settime]	= PLEDGE_SETTIME,
	[SYS_clock_getres]	= PLEDGE_STDIO,
	[SYS_ktimer_create]	= PLEDGE_STDIO,
	[SYS_ktimer_delete]	= PLEDGE_STDIO,
	[SYS_ktimer_settime]	= PLEDGE_STDIO,
	[SYS_ktimer_gettime]	= PLEDGE_STDIO,
	[SYS_ktimer_getoverrun]	= PLEDGE_STDIO,
	/* 240: */
	[SYS_nanosleep]		= PLEDGE_NONE,
	[SYS_ffclock_getcounter]	= PLEDGE_STDIO,
	[SYS_ffclock_setestimate]	= PLEDGE_STDIO,
	[SYS_ffclock_getestimate]	= PLEDGE_STDIO,
	[SYS_clock_nanosleep]		= PLEDGE_NONE,
	[SYS_clock_getcpuclockid2]	= PLEDGE_STDIO,
	[SYS_ntp_gettime]		= PLEDGE_STDIO,
	/* 250: */
	[SYS_minherit]	= PLEDGE_STDIO,
	[SYS_rfork]	= PLEDGE_PROC | PLEDGE_STDIO,
	[SYS_issetugid]	= PLEDGE_NONE,
	[SYS_lchown]	= PLEDGE_CHOWN, // chown
	[SYS_aio_read]	= PLEDGE_AND | PLEDGE_AIO, // TODO
	[SYS_aio_write]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO, // TODO
	[SYS_lio_listio]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO, // like preadv/pwritev for aio?
	/* 272 */
	[SYS_freebsd11_getdents]	= PLEDGE_RPATH,
	[SYS_lchmod]	= PLEDGE_FATTR,
#ifdef SYS_netbsd_lchown
	[SYS_netbsd_lchown]	= PLEDGE_CHOWN, // chown
#endif
	[SYS_lutimes]	= PLEDGE_FATTR,
#ifdef SYS_netbsd_msync
	[SYS_netbsd_msync]	= PLEDGE_STDIO, // TODO
#endif
	[SYS_freebsd11_nstat]	= PLEDGE_RPATH,
	[SYS_freebsd11_nfstat]	= PLEDGE_RPATH,
	/* 280: */
	[SYS_freebsd11_nlstat]	= PLEDGE_RPATH,
	[SYS_preadv]	= PLEDGE_STDIO,
	/* 290: */
	[SYS_pwritev]	= PLEDGE_STDIO,
	[SYS_fhopen]	= PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_freebsd11_fhstat]	= PLEDGE_RPATH | PLEDGE_WPATH,
	/* 300: */
	[SYS_modnext]	= PLEDGE_KLD,
	[SYS_modstat]	= PLEDGE_KLD,
	[SYS_modfnext]	= PLEDGE_KLD,
	[SYS_modfind]	= PLEDGE_KLD,
	[SYS_kldload]	= PLEDGE_AND | PLEDGE_EXEC | PLEDGE_KLD | PLEDGE_RPATH,
	[SYS_kldunload]	= PLEDGE_KLD,
	[SYS_kldfind]	= PLEDGE_KLD,
	[SYS_kldnext]	= PLEDGE_KLD,
	[SYS_kldstat]	= PLEDGE_KLD,
	[SYS_kldfirstmod]	= PLEDGE_KLD,
	/* 310: */
	[SYS_getsid]	= PLEDGE_STDIO,
	[SYS_setresuid]	= PLEDGE_ID,
	[SYS_setresgid]	= PLEDGE_ID,
	[SYS_aio_return]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_aio_suspend]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_aio_cancel]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_aio_error]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_yield]	= PLEDGE_NONE,
	[SYS_mlockall]	= PLEDGE_STDIO,
	[SYS_munlockall]	= PLEDGE_STDIO,
	[SYS___getcwd]	= PLEDGE_STDIO,
	[SYS_sched_setparam]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_getparam]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_setscheduler]= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	/* 330: */
	[SYS_sched_getscheduler]= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_yield]	= PLEDGE_NONE,
	[SYS_sched_get_priority_max]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_get_priority_min]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_rr_get_interval]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_utrace]	= PLEDGE_KLD,
	[SYS_kldsym]	= PLEDGE_KLD,
	[SYS_jail]	= PLEDGE_PROC,
	[SYS_nnpfs_syscall]	= PLEDGE_KLD,
	/* 340: */
	[SYS_sigprocmask]	 = PLEDGE_STDIO,
	[SYS_sigsuspend]	 = PLEDGE_STDIO,
	[SYS_sigpending]	 = PLEDGE_STDIO,
	[SYS_sigtimedwait] = PLEDGE_STDIO,
	[SYS_sigwaitinfo]	 = PLEDGE_STDIO,
	[SYS___acl_get_file]	= PLEDGE_AND | PLEDGE_RPATH | PLEDGE_FATTR,
	[SYS___acl_set_file]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_FATTR,
	[SYS___acl_get_fd]	= PLEDGE_FATTR,
	/* 350: */
	[SYS___acl_set_fd]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_FATTR,
	[SYS___acl_delete_file]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_FATTR,
	[SYS___acl_delete_fd]	=  PLEDGE_AND | PLEDGE_CPATH | PLEDGE_FATTR,
	[SYS___acl_aclcheck_file]	=  PLEDGE_AND | PLEDGE_RPATH | PLEDGE_FATTR,
	[SYS___acl_aclcheck_fd]	=  PLEDGE_AND | PLEDGE_RPATH | PLEDGE_FATTR,
	[SYS_extattrctl]	= PLEDGE_FATTR,
	[SYS_extattr_set_file]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_FATTR,
	[SYS_extattr_get_file]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_RPATH,
	[SYS_extattr_delete_file]	= PLEDGE_CPATH,
	[SYS_aio_waitcomplete]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	/* 360: */
	[SYS_getresuid]	= PLEDGE_STDIO,
	[SYS_getresgid]	= PLEDGE_STDIO,
	[SYS_kqueue]	= PLEDGE_STDIO, /* TODO */
	[SYS_freebsd11_kevent]	= PLEDGE_STDIO, /* 363, TODO */
	[SYS_extattr_set_fd]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_WPATH,
	[SYS_extattr_get_fd]	= PLEDGE_RPATH,
	[SYS_extattr_delete_fd]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS___setugid]	= PLEDGE_ID,
	[SYS_eaccess]	= PLEDGE_RPATH,
	[SYS_afs3_syscall]	= PLEDGE_STDIO, /* TODO */
	[SYS_nmount]	= PLEDGE_DEVICE,
	[SYS___mac_get_proc]	= PLEDGE_STDIO,
	[SYS___mac_set_proc]	= PLEDGE_STDIO, /* TODO */
	[SYS___mac_get_fd]	= PLEDGE_STDIO,
	[SYS___mac_get_file]	= PLEDGE_FATTR,
	[SYS___mac_set_fd]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_FATTR, /* TODO */
	[SYS___mac_set_file]	= PLEDGE_FATTR, /* TODO */
	/* 390: */
	[SYS_kenv]	= PLEDGE_SYSCTL,
	[SYS_lchflags]	= PLEDGE_FATTR,
	[SYS_uuidgen]	= PLEDGE_STDIO, // leaks mac address so...
	[SYS_sendfile]	= PLEDGE_STDIO,
	[SYS_mac_syscall]	= PLEDGE_STDIO, /* TODO */
	[SYS_freebsd11_getfsstat]	= PLEDGE_RPATH,
	[SYS_freebsd11_statfs]	= PLEDGE_RPATH,
	[SYS_freebsd11_fstatfs]	= PLEDGE_RPATH,
	[SYS_freebsd11_fhstatfs]	= PLEDGE_RPATH,
	/* 400: */
	[SYS_ksem_close]	= PLEDGE_STDIO,
	[SYS_ksem_post]	= PLEDGE_STDIO, /* TODO */
	[SYS_ksem_wait]	= PLEDGE_STDIO,
	[SYS_ksem_trywait]	= PLEDGE_STDIO,
	[SYS_ksem_init]	= PLEDGE_STDIO,
	[SYS_ksem_open]	= PLEDGE_STDIO,
	[SYS_ksem_unlink]	= PLEDGE_STDIO,
	[SYS_ksem_getvalue]	= PLEDGE_STDIO,
	[SYS_ksem_destroy]	= PLEDGE_STDIO,
	[SYS___mac_get_pid]	= PLEDGE_STDIO,
	/* 410: */
	[SYS___mac_get_link]	= PLEDGE_FATTR,
	[SYS___mac_set_link]	= PLEDGE_FATTR,
	[SYS_extattr_set_link]	= PLEDGE_CPATH,
	[SYS_extattr_get_link]	= PLEDGE_RPATH,
	[SYS_extattr_delete_link]	= PLEDGE_CPATH,
	[SYS___mac_execve]	= PLEDGE_EXEC,
	[SYS_sigaction]	= PLEDGE_STDIO,
	[SYS_sigreturn]	= PLEDGE_STDIO,
	[SYS_getcontext]	= PLEDGE_STDIO,
	[SYS_setcontext]	= PLEDGE_STDIO,
	[SYS_swapcontext]	= PLEDGE_STDIO,
	[SYS___acl_get_link]	= PLEDGE_FATTR,
	[SYS___acl_set_link]	= PLEDGE_FATTR,
	[SYS___acl_delete_link]	= PLEDGE_FATTR,
	[SYS___acl_aclcheck_link]	= PLEDGE_FATTR,
	[SYS_sigwait]	= PLEDGE_STDIO,
	/* 430: */
	[SYS_thr_create]	= PLEDGE_PROC, // TODO
	[SYS_thr_exit]	= PLEDGE_NONE,
	[SYS_thr_self]	= PLEDGE_STDIO,
	[SYS_thr_kill]	= PLEDGE_PROC,
	[SYS_jail_attach]	= PLEDGE_PROC,
	[SYS_extattr_list_fd]	= PLEDGE_RPATH,
	[SYS_extattr_list_file]	= PLEDGE_RPATH,
	[SYS_extattr_list_link]	= PLEDGE_RPATH,
	[SYS_ksem_timedwait]	= PLEDGE_STDIO,
	[SYS_thr_suspend]	= PLEDGE_PROC,
	[SYS_thr_wake]	= PLEDGE_PROC,
	[SYS_kldunloadf]	= PLEDGE_KLD,
	[SYS_audit]	= PLEDGE_STDIO,
	[SYS_auditon]	= PLEDGE_STDIO,
	[SYS_getauid]	= PLEDGE_STDIO,
	[SYS_setauid]	= PLEDGE_ID,
	[SYS_getaudit]	= PLEDGE_STDIO,
	/* 450: */
	[SYS_setaudit]	= PLEDGE_STDIO,
	[SYS_getaudit_addr]	= PLEDGE_STDIO,
	[SYS_setaudit_addr]	= PLEDGE_STDIO,
	[SYS_auditctl]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_DEVICE, /* TODO */
	[SYS__umtx_op]	= PLEDGE_STDIO,
	[SYS_thr_new]	= PLEDGE_STDIO,
	[SYS_sigqueue]	= PLEDGE_STDIO,
	[SYS_kmq_open]	= PLEDGE_STDIO,
	[SYS_kmq_setattr]	= PLEDGE_STDIO,
	[SYS_kmq_timedreceive]	= PLEDGE_STDIO,
	/* 460: */
	[SYS_kmq_timedsend]	= PLEDGE_STDIO,
	[SYS_kmq_notify]	= PLEDGE_STDIO,
	[SYS_kmq_unlink]	= PLEDGE_STDIO,
	[SYS_abort2]	= PLEDGE_STDIO,
	[SYS_thr_set_name]	= PLEDGE_STDIO,
	[SYS_aio_fsync]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_rtprio_thread]	= PLEDGE_STDIO,
	[SYS_sctp_peeloff]	= PLEDGE_INET, /* TODO ... */
	[SYS_sctp_generic_sendmsg]	= PLEDGE_INET,
	[SYS_sctp_generic_sendmsg_iov]	= PLEDGE_INET,
	[SYS_sctp_generic_recvmsg]	= PLEDGE_INET,
	[SYS_pread]	= PLEDGE_NONE,
	[SYS_pwrite]	= PLEDGE_NONE,
	[SYS_mmap]	= PLEDGE_STDIO,
	[SYS_lseek]	= PLEDGE_STDIO, // TODO consider append-only?
	[SYS_truncate]	= PLEDGE_WPATH,
	/* 480: */
	[SYS_ftruncate]	= PLEDGE_NONE, /* that is openat's problem */
	[SYS_thr_kill2]	= PLEDGE_STDIO,
#ifdef SYS_freebsd12_shm_open
	[SYS_freebsd12_shm_open] = PLEDGE_RPATH | PLEDGE_WPATH, /* TODO */
#elif SYS_shm_open
	[SYS_shm_open]	= PLEDGE_RPATH | PLEDGE_WPATH, /* TODO */
#endif
	[SYS_shm_unlink]	= PLEDGE_CPATH,
	[SYS_cpuset]	= PLEDGE_STDIO,
	[SYS_cpuset_setid]	= PLEDGE_STDIO,
	[SYS_cpuset_getid]	= PLEDGE_STDIO,
	[SYS_cpuset_getaffinity]	= PLEDGE_STDIO,
	[SYS_cpuset_setaffinity]	= PLEDGE_STDIO,
	[SYS_faccessat]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH | PLEDGE_NOLEARN, // TODO this should probably softfail?
	/* 490: */
	[SYS_fchmodat]	= PLEDGE_FATTR,
	[SYS_fchownat]	= PLEDGE_CHOWN, // chownbecause
	[SYS_fexecve]	= PLEDGE_EXEC,
#ifdef SYS_freebsd11_fstatat
	/* this is a bit ugly, we have a definition for
	 SYS_fstatat further below. would be nice to have
	 them in the same place. TODO */
	[SYS_freebsd11_fstatat]	= PLEDGE_RPATH,
#endif
	[SYS_futimesat]	= PLEDGE_FATTR,
	[SYS_linkat]	= PLEDGE_CPATH,
	[SYS_mkdirat]	= PLEDGE_CPATH,
	[SYS_mkfifoat]	= PLEDGE_CPATH,
#ifdef SYS_freebsd11_mknodat
	[SYS_freebsd11_mknodat]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#else
	[SYS_mknodat]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#endif
	[SYS_openat]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH | PLEDGE_NOLEARN,
	/* 500: */
	[SYS_readlinkat]	= PLEDGE_RPATH,
	[SYS_renameat]	= PLEDGE_CPATH,
	[SYS_symlinkat]	= PLEDGE_CPATH,
	[SYS_unlinkat]	= PLEDGE_CPATH,
	[SYS_posix_openpt]	= PLEDGE_TTY,
#ifdef SYS_gssd_syscall
	[SYS_gssd_syscall]	= PLEDGE_STDIO, /* TODO */
#endif
	[SYS_jail_get]	= PLEDGE_PROC, // TODO consider pledge flag for this
	[SYS_jail_set]	= PLEDGE_PROC,
	[SYS_jail_remove]	= PLEDGE_PROC,
#ifdef SYS_closefrom
	[SYS_closefrom]	= PLEDGE_STDIO,
#endif
	/* 510: */
	[SYS___semctl]	= PLEDGE_STDIO,
	[SYS_msgctl]	= PLEDGE_STDIO,
	[SYS_shmctl]	= PLEDGE_STDIO,
	[SYS_lpathconf]	= PLEDGE_STDIO, // TODO
	[SYS___cap_rights_get]	= PLEDGE_CAPSICUM, // TODO?
	[SYS_cap_enter]	= PLEDGE_CAPSICUM,
	[SYS_cap_getmode]	= PLEDGE_CAPSICUM,
	[SYS_pdfork]	= PLEDGE_PROC,
	[SYS_pdkill]	= PLEDGE_PROC,
	/* 520: */
	[SYS_pdgetpid]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_pselect]	= PLEDGE_STDIO,
	[SYS_getloginclass]	= PLEDGE_STDIO,
	[SYS_setloginclass]	= PLEDGE_STDIO,
	[SYS_rctl_get_racct]	= PLEDGE_STDIO,
	[SYS_rctl_get_rules]	= PLEDGE_STDIO,
	[SYS_rctl_get_limits]	= PLEDGE_STDIO,
	[SYS_rctl_add_rule]	= PLEDGE_STDIO,
	[SYS_rctl_remove_rule]	= PLEDGE_STDIO,
	/* 530: */
	[SYS_posix_fallocate]	= PLEDGE_STDIO,
	[SYS_posix_fadvise]	= PLEDGE_STDIO,
	[SYS_wait6]		= PLEDGE_STDIO,
	[SYS_cap_rights_limit]	= PLEDGE_CAPSICUM,
	[SYS_cap_ioctls_limit]	= PLEDGE_CAPSICUM,
	[SYS_cap_ioctls_get]	= PLEDGE_CAPSICUM,
	[SYS_cap_fcntls_limit]	= PLEDGE_CAPSICUM,
	[SYS_cap_fcntls_get]	= PLEDGE_CAPSICUM,
	[SYS_bindat]		= PLEDGE_UNIX,
	[SYS_connectat]	= PLEDGE_UNIX,
	/* 540: */
	[SYS_chflagsat]	= PLEDGE_FATTR,
	[SYS_accept4]		= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_pipe2]		= PLEDGE_STDIO,
	[SYS_aio_mlock]	= PLEDGE_AND | PLEDGE_AIO | PLEDGE_STDIO,
	[SYS_procctl]		= PLEDGE_PROC,
	[SYS_ppoll]		= PLEDGE_STDIO,
	[SYS_futimens]		= PLEDGE_FATTR,
	[SYS_utimensat]	= PLEDGE_FATTR,
	/* 550: */
	[SYS_fdatasync]	= PLEDGE_STDIO,
/* at this point twenty new syscalls were added (around 13-CURRENT).*/
#ifdef SYS_fstat
	[SYS_fstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fstatat
	[SYS_fstatat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fhstat
	[SYS_fhstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_getdirentries
	[SYS_getdirentries] = PLEDGE_RPATH,
#endif
#ifdef SYS_statfs
	[SYS_statfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fstatfs
	[SYS_fstatfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_getfsstat
	[SYS_getfsstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fhstatfs
	[SYS_fhstatfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_mknodat
	[SYS_mknodat] = PLEDGE_AND | PLEDGE_DEVICE | PLEDGE_CPATH, /*  */
#endif
/* 560: */
#ifdef SYS_kevent
	[SYS_kevent] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_cpuset_getdomain
	[SYS_cpuset_getdomain] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_cpuset_setdomain
	[SYS_cpuset_setdomain] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_getrandom
	[SYS_getrandom] = PLEDGE_NONE, /* */
#endif
#ifdef SYS_getfhat
	[SYS_getfhat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fhlink
	[SYS_fhlink] = PLEDGE_CPATH, /*  */
#endif
#ifdef SYS_fhlinkat
	[SYS_fhlinkat] = PLEDGE_CPATH, /*  */
#endif
#ifdef SYS_fhreadlink
	[SYS_fhreadlink] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_funlinkat
	[SYS_funlinkat] = PLEDGE_CPATH, /*  */
#endif
#ifdef SYS_copy_file_range
	[SYS_copy_file_range] = PLEDGE_STDIO, /*  */
#endif
/* 570: */
#ifdef SYS___sysctlbyname
	/* checked by kern_sysctl.c */
	[SYS___sysctlbyname] = PLEDGE_SYSCTL,
#endif
#ifdef SYS_shm_open2
	[SYS_shm_open2] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_shm_rename
	[SYS_shm_rename] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_sigfastblock
	[SYS_sigfastblock] = PLEDGE_STDIO, /*  */
#endif
/* 574: */
#ifdef SYS___realpathat
	[SYS___realpathat] = PLEDGE_RPATH, /* 574 */
#endif
#ifdef SYS_close_range
	[SYS_close_range] = PLEDGE_STDIO, /* 575 */
#endif
#ifdef SYS_rpctls_syscall
	[SYS_rpctls_syscall] = PLEDGE_STDIO, /* 576 */
#endif
#ifdef SYS___specialfd
	[SYS___specialfd] = PLEDGE_STDIO, /* 577 */
#endif
#ifdef SYS_aio_writev
	[SYS_aio_writev] = PLEDGE_AND | PLEDGE_AIO, /* 578 */
#endif
#ifdef SYS_aio_readv
	[SYS_aio_readv] = PLEDGE_AND |  PLEDGE_AIO, /* 579 */
#endif
#ifdef SYS_sched_getcpu
	[SYS_sched_getcpu] = PLEDGE_NONE, /* 581 */
#endif
#ifdef SYS_swapoff
	[SYS_swapoff] = PLEDGE_KLD, /* 582 */
#endif
#ifdef SYS_kqueuex
	[SYS_kqueuex] = PLEDGE_NONE, /* 583 */
#endif
#ifdef SYS_membarrier
	[SYS_membarrier] = PLEDGE_NONE, /* 584 */
#endif
#ifdef SYS_timerfd_create
	[SYS_timerfd_create] = PLEDGE_NONE, /* 585 */
#endif
#ifdef SYS_timerfd_gettime
	[SYS_timerfd_gettime] = PLEDGE_NONE, /* 586 */
#endif
#ifdef SYS_timerfd_settime
	[SYS_timerfd_settime] = PLEDGE_NONE, /* 587 */
#endif
#ifdef SYS_kcmp
	[SYS_kcmp] = PLEDGE_NONE, /* 588 */
#endif
#ifdef SYS_getrlimitusage
	[SYS_getrlimitusage] = PLEDGE_NONE, /* 589 */
#endif
#ifdef SYS_fchroot
	[SYS_fchroot] = PLEDGE_DEVICE, /* 590 */
#endif
#ifdef SYS_setcred
	[SYS_setcred] = PLEDGE_ID, /* 591 */
#endif
#ifdef SYS_exterrctl
	[SYS_exterrctl] = PLEDGE_PROC, /* 592 */
#endif
#ifdef SYS_inotify_add_watch_at
	[SYS_inotify_add_watch_at] = PLEDGE_RPATH, /* 593 */
#endif
#ifdef SYS_inotify_rm_watch
	[SYS_inotify_rm_watch] = PLEDGE_RPATH, /* 594 */
#endif
#ifdef SYS_getgroups
	[SYS_getgroups] = PLEDGE_STDIO, /* 595 */
#endif
#ifdef SYS_setgroups
	[SYS_setgroups] = PLEDGE_ID, /* 596 */
#endif
#ifdef SYS_jail_attach_jd
	[SYS_jail_attach_jd] = PLEDGE_PROC, /* 597 */
#endif
#ifdef SYS_jail_remove_jd
	[SYS_jail_remove_jd] = PLEDGE_PROC, /* 598 */
#endif
#ifdef SYS_kexec_load
	[SYS_kexec_load] = PLEDGE_KLD | PLEDGE_DEVICE, /* 599 */
#endif
#ifdef SYS_pdrfork
	[SYS_pdrfork] = PLEDGE_PROC, /* 600 */
#endif
#ifdef SYS_pdwait
	[SYS_pdwait] = PLEDGE_PROC, /* 601 */
#endif
#ifdef SYS_renameat2
	[SYS_renameat2] = PLEDGE_CPATH, /* 602 */
#endif
#ifdef SYS_pdopenpid
	[SYS_pdopenpid] = PLEDGE_NONE, /* 603 */
#endif
#ifdef SYS_pddupfd
	[SYS_pddupfd] = PLEDGE_NONE, /* 604 */
#endif
#ifdef SYS_pdptrace
	[SYS_pdptrace] = PLEDGE_NONE, /* 605 */
#endif
};
_Static_assert(603 == SYS_MAXSYSCALL, "new syscalls added to sys/sys/syscall.h, hbsd_pledge.c needs to be updated. TODO would it make sense to remove this static assertion and instead display a helpful message on boot + allow the operator to declare/override the defaults via tunables to prevent situations where people can't boot after upgrading?");

/*
 * Hook used to determine whether a given syscall should be called or not.
 * Main caller is sys/kern/subr_syscall.c:syscallenter
 */
int inline
pledge_syscall(struct thread * thread, const int syscall_no)
{
	if (syscall_no < 0 || SYS_MAXSYSCALL <= syscall_no) {
		/* to prevent out-of-bounds access to pledge_permission_map,
		 * default to requiring all privileges in this case,
		 * (TODO and soft-failing would be good)
		 * (prevents breakage when enforcing is off and new
		 * syscalls have been added): */
		return (pledge_check_bitmap(thread,
			PLEDGE_AND | PLEDGE_WILDCARD));
	}

	if (syscall_no == SYS___sysctl || syscall_no == SYS___sysctlbyname)
		return (0); /* checked in kern_sysctl.c */

	return (pledge_check_bitmap(thread, pledge_permission_map[syscall_no]));
}

#ifdef HBSD_PLEDGE_MAC
// HBSD_PLEDGE_MAC is not defined, this is commented out because the MAC stuff is rean't really implemented yety
/*
 * TODO here we define hooks for the mac framework, which alleviates
 * the need to add hooks manually everywhere.
 * see https://www.freebsd.org/doc/en_US.ISO8859-1/books/arch-handbook/mac-entry-point-reference.html#mac-access-control-checks
 */
static struct mac_policy_ops mac_pledge_ops =
{
	/*
	 * sys/security/mac_stub/mac_stub.c
	 */
	// this takes an extra argument: .mpo_syscall = pledge_syscall,
	// .mpo_vnode_check_open / .mpo_check_vnode_access(struct ucred *cred, struct vnode *vp, struct label *label, int flags)
	// .mpo_check_socket_connect
	// .mpo_check_system_sysctl
	NULL
};

MAC_POLICY_SET(&mac_pledge_ops, mac_pledge, "HardenedBSD MAC/pledge",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);
#endif /* HBSD_PLEDGE_MAC */

#endif /* ifdef HBSD_PLEDGE */
