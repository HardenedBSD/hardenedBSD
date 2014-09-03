/*-
 * Copyright (c) 2014, by David Carlier <devnexen at gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ptrace_hardening.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/libkern.h>
#include <sys/ptrace_hardening.h>

#include <sys/syslimits.h>
#include <sys/param.h>

int ptrace_hardening_status = 0;
#ifdef PTRACE_HARDENING_GRP
gid_t ptrace_hardening_allowed_gid = 0;
#endif

TUNABLE_INT("security.ptrace.hardening.status", &ptrace_hardening_status);
#ifdef PTRACE_HARDENING_GRP
TUNABLE_INT("security.ptrace.hardening.allowed_gid", &ptrace_hardening_allowed_gid);
#endif

static int sysctl_ptrace_hardening_status(SYSCTL_HANDLER_ARGS);
#ifdef PTRACE_HARDENING_GRP
static int sysctl_ptrace_hardening_gid(SYSCTL_HANDLER_ARGS);
#endif

SYSCTL_DECL(_security);
SYSCTL_DECL(_security_ptrace);

SYSCTL_NODE(_security, OID_AUTO, ptrace, CTLFLAG_RD, 0,
    "PTrace setting.");
SYSCTL_NODE(_security_ptrace, OID_AUTO, hardening, CTLFLAG_RD, 0,
    "PTrace hardening (calls restrictions).");

SYSCTL_PROC(_security_ptrace_hardening, OID_AUTO, status, 
            CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE, 
            NULL, 0, sysctl_ptrace_hardening_status, "I",
            "Restrictions status. "
            "0 - disabled, "
            "1 - enabled");

#ifdef PTRACE_HARDENING_GRP
SYSCTL_PROC(_security_ptrace_hardening, OID_AUTO, gid,
            CTLTYPE_UINT|CTLFLAG_RW|CTLFLAG_PRISON|CTLFLAG_SECURE,
            NULL, 0, sysctl_ptrace_hardening_gid, "U",
            "Allowed gid");
#endif

int
sysctl_ptrace_hardening_status(SYSCTL_HANDLER_ARGS)
{
    int err, val;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || (req->newptr == NULL))
        return (err);

    switch(val) {
    case PTRACE_HARDENING_DISABLED:
    case PTRACE_HARDENING_ENABLED:
        ptrace_hardening_status = val;
    default:
        return (EINVAL);
    }

    return (0);
}

int
sysctl_ptrace_hardening_gid(SYSCTL_HANDLER_ARGS)
{
    int err;
    uint64_t val;
    err = sysctl_handle_64(oidp, &val, sizeof(uint64_t), req);
    if (err || (req->newptr == NULL))
        return (err);

    ptrace_hardening_allowed_gid = (gid_t)val;
    return (0);
}

int
ptrace_hardening(struct thread *td, pid_t pid)
{
    uid_t uid = td->td_ucred->cr_ruid;
#ifdef PTRACE_HARDENING_CHLD
    struct proc *cchild = NULL;
    sx_init(&proctree_lock);
#endif
#ifdef PTRACE_HARDENING_GRP
    gid_t gid = td->td_ucred->cr_rgid;
    if (uid || gid != ptrace_hardening_allowed_gid)
        return (EPERM);
#else
    if (uid)
        return (EPERM);
#endif
#ifdef PTRACE_HARDENING_CHLD
    sx_xlock(&proctree_lock);
    LIST_FOREACH(cchild, &td->td_proc->p_children, 
                 p_sibling) {
        PROC_LOCK(cchild);
        if (cchild->p_pid == pid) {
            PROC_UNLOCK(cchild);
            sx_xunlock(&proctree_lock);
            return (0);
        }
        PROC_UNLOCK(cchild);
    }
    sx_xunlock(&proctree_lock);
    
    return (EPERM);
#endif
    return (0);
}
