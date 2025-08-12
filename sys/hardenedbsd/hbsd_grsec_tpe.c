/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Shawn Webb <shawn.webb@hardenedbsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include <sys/cdefs.h>

#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include "hbsd_pax_internal.h"

FEATURE(hbsd_tpe, "Trusted Path Execution.");

static int pax_tpe_global = PAX_FEATURE_OPTIN;
static int pax_tpe_gid = 0;
static int pax_tpe_negate = 0;
static int pax_tpe_all = 0;
static int pax_tpe_root_owned = 1;
static int pax_tpe_user_owned = 0;

TUNABLE_INT("hardening.tpe.status", &pax_tpe_global);
TUNABLE_INT("hardening.tpe.gid", &pax_tpe_gid);
TUNABLE_INT("hardening.tpe.negate", &pax_tpe_negate);
TUNABLE_INT("hardening.tpe.all", &pax_tpe_all);
TUNABLE_INT("hardening.tpe.root_owned", &pax_tpe_root_owned);
TUNABLE_INT("hardening.tpe.user_owned", &pax_tpe_user_owned);

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);
SYSCTL_NODE(_hardening_pax, OID_AUTO, tpe, CTLFLAG_RD, 0,
    "Settings for Trusted Path Execution (TPE).");

SYSCTL_HBSD_4STATE(pax_tpe_global, pr_hbsd.hardening.tpe,
    _hardening_pax_tpe, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);

static int sysctl_pax_tpe_gid(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_hardening_pax_tpe, OID_AUTO, gid,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON, NULL, 0,
    sysctl_pax_tpe_gid, "I",
    "Untrusted TPE GID");

static int sysctl_pax_tpe_negate(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_hardening_pax_tpe, OID_AUTO, negate,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON, NULL, 0,
    sysctl_pax_tpe_negate, "I",
    "Negate TPE GID logic");

static int sysctl_pax_tpe_all(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_hardening_pax_tpe, OID_AUTO, all,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON, NULL, 0,
    sysctl_pax_tpe_all, "I",
    "Apply TPE to all users");

static int sysctl_pax_tpe_root_owned(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_hardening_pax_tpe, OID_AUTO, root_owned,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON, NULL, 0,
    sysctl_pax_tpe_root_owned, "I",
    "Ensure directory is root-owned");

static int sysctl_pax_tpe_user_owned(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_hardening_pax_tpe, OID_AUTO, user_owned,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON, NULL, 0,
    sysctl_pax_tpe_user_owned, "I",
    "Ensure directory is user-owned");
#endif

#ifdef PAX_JAIL_SUPPORT
SYSCTL_DECL(_security_jail_param_hardening);
SYSCTL_DECL(_security_jail_param_hardening_pax);
SYSCTL_DECL(_security_jail_param_hardening_pax_tpe);
SYSCTL_JAIL_PARAM_SUBNODE(hardening_pax, tpe, "TPE");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, status,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "TPE status");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, gid,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "Untrusted TPE GID");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, negate,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "Negate TPE GID logic");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, all,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "Apply TPE to all users");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, root_only,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "Ensure directory is root-owned");
SYSCTL_JAIL_PARAM(_hardening_pax_tpe, user_only,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "Ensure directory is user-owned");
#endif

static bool _pax_tpe_active(struct thread *);
static int _pax_tpe_vap(struct thread *, struct prison *, struct vattr *);

int
pax_tpe_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;
	int error;

	if (pr == &prison0) {
		pr->pr_hbsd.hardening.tpe = pax_tpe_global;
		pr->pr_hbsd.hardening.tpe_gid = pax_tpe_gid;
		pr->pr_hbsd.hardening.tpe_negate = pax_tpe_negate;
		pr->pr_hbsd.hardening.tpe_all = pax_tpe_all;
		pr->pr_hbsd.hardening.tpe_root_owned = pax_tpe_root_owned;
		pr->pr_hbsd.hardening.tpe_user_owned = pax_tpe_user_owned;
	} else {
		pr_p = pr->pr_parent;
		pr->pr_hbsd.hardening.tpe = pr_p->pr_hbsd.hardening.tpe;
		pr->pr_hbsd.hardening.tpe_gid = pr_p->pr_hbsd.hardening.tpe_gid;
		pr->pr_hbsd.hardening.tpe_negate = pr_p->pr_hbsd.hardening.tpe_negate;
		pr->pr_hbsd.hardening.tpe_all = pr_p->pr_hbsd.hardening.tpe_all;
		pr->pr_hbsd.hardening.tpe_root_owned = pr_p->pr_hbsd.hardening.tpe_root_owned;
		pr->pr_hbsd.hardening.tpe_user_owned = pr_p->pr_hbsd.hardening.tpe_user_owned;

		error = pax_handle_prison_param(opts, "hardening.pax.tpe.status",
		    &(pr->pr_hbsd.hardening.tpe));
		if (error != 0) {
			return (error);
		}
		error = pax_handle_prison_param(opts, "hardening.pax.tpe.gid",
		    &(pr->pr_hbsd.hardening.tpe_gid));
		if (error != 0) {
			return (error);
		}
		error = pax_handle_prison_param(opts, "hardening.pax.tpe.negate",
		    &(pr->pr_hbsd.hardening.tpe_negate));
		if (error != 0) {
			return (error);
		}
		error = pax_handle_prison_param(opts, "hardening.pax.tpe.all",
		    &(pr->pr_hbsd.hardening.tpe_all));
		if (error != 0) {
			return (error);
		}
		error = pax_handle_prison_param(opts, "hardening.pax.tpe.root_owned",
		    &(pr->pr_hbsd.hardening.tpe_root_owned));
		if (error != 0) {
			return (error);
		}
		error = pax_handle_prison_param(opts, "hardening.pax.tpe.user_owned",
		    &(pr->pr_hbsd.hardening.tpe_user_owned));
		if (error != 0) {
			return (error);
		}
	}

	return (0);
}

pax_flag_t
pax_tpe_setup_flags(struct image_params *imgp, struct thread *td,
    pax_flag_t mode)
{
	struct prison *pr;
	pax_flag_t flags;
	uint32_t status;

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.hardening.tpe;
	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_TPE;
		flags |= PAX_NOTE_NOTPE;
		return (flags);
	}
	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= PAX_NOTE_TPE;
		flags &= ~PAX_NOTE_NOTPE;
		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if ((mode & PAX_NOTE_TPE) == PAX_NOTE_TPE) {
			flags |= PAX_NOTE_TPE;
			flags &= ~PAX_NOTE_NOTPE;
		} else {
			flags &= ~PAX_NOTE_TPE;
			flags |= PAX_NOTE_NOTPE;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if ((mode & PAX_NOTE_NOTPE) == PAX_NOTE_NOTPE) {
			flags &= ~PAX_NOTE_TPE;
			flags |= PAX_NOTE_NOTPE;
		} else {
			flags |= PAX_NOTE_TPE;
			flags &= ~PAX_NOTE_NOTPE;
		}
		return (flags);
	}

	flags |= PAX_NOTE_TPE;
	flags &= ~PAX_NOTE_NOTPE;

	return (flags);
}

int
pax_enforce_tpe(struct thread *td, struct vnode *vn, const char *path)
{
	char *parent_path, *tmp;
	struct nameidata nd;
	struct prison *pr;
	struct vattr vap;
	int error;

	if (td == NULL || vn == NULL || path == NULL) {
		return (EDOOFUS);
	}

	pr = pax_get_prison_td(td);
	if (pr->pr_hbsd.hardening.tpe == PAX_FEATURE_DISABLED) {
		return (0);
	}

	if (!_pax_tpe_active(td)) {
		return (0);
	}

	tmp = strrchr(path, '/');
	if (tmp == NULL) {
		return (EDOOFUS);
	}
	if (strlen(tmp) < 2) {
		return (0);
	}

	parent_path = malloc((tmp - path) + 1, M_TEMP,
	    M_WAITOK | M_ZERO);
	strncpy(parent_path, path, tmp - path);

	error = VOP_LOCK(vn, LK_SHARED);
	if (error) {
		free(parent_path, M_TEMP);
		return (error);
	}

	memset(&vap, 0, sizeof(vap));
	error = VOP_GETATTR(vn, &vap, td->td_ucred);
	if (error) {
		free(parent_path, M_TEMP);
		return (error);
	}

	VOP_UNLOCK(vn);

	error = _pax_tpe_vap(td, pr, &vap);
	if (error) {
		free(parent_path, M_TEMP);
		return (error);
	}

	memset(&nd, 0, sizeof(nd));
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, parent_path);
	nd.ni_debugflags |= NAMEI_DBG_INITED;
	error = namei(&nd);
	if (error) {
		free(parent_path, M_TEMP);
		NDFREE_PNBUF(&nd);
		return (error);
	}

	memset(&vap, 0, sizeof(vap));
	error = VOP_GETATTR(nd.ni_vp, &vap, td->td_ucred);
	if (error) {
		goto end;
	}

	error = _pax_tpe_vap(td, pr, &vap);
	if (error) {
		goto end;
	}

end:
	VOP_UNLOCK(nd.ni_vp);
	NDFREE_PNBUF(&nd);
	free(parent_path, M_TEMP);
	return (error);
}

static bool
_pax_tpe_active(struct thread *td)
{
	struct prison *pr;
	pax_flag_t flags;

	pr = pax_get_prison_td(td);
	pax_get_flags(td->td_proc, &flags);
	if ((flags & PAX_NOTE_NOTPE) == PAX_NOTE_NOTPE) {
		return (false);
	}

	if (pr->pr_hbsd.hardening.tpe_all) {
		return (true);
	}

	if (td->td_ucred->cr_gid == pr->pr_hbsd.hardening.tpe_gid) {
		return (pr->pr_hbsd.hardening.tpe_negate == 0);
	}

	return (pr->pr_hbsd.hardening.tpe_negate != 0);
}

static int
_pax_tpe_vap(struct thread *td, struct prison *pr, struct vattr *vap)
{
	if (pr->pr_hbsd.hardening.tpe_root_owned) {
		if (vap->va_uid != 0) {
			return (EPERM);
		}
	}

	if (pr->pr_hbsd.hardening.tpe_user_owned && td->td_ucred->cr_uid != 0) {
		if (vap->va_uid != 0 && vap->va_uid != td->td_ucred->cr_uid) {
			return (EPERM);
		}
	}

	if ((vap->va_mode & (S_IWGRP | S_IWOTH)) != 0) {
		return EPERM;
	}

	return (0);
}

#ifdef PAX_SYSCTLS
static int
sysctl_pax_tpe_gid(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);
	val = pr->pr_hbsd.hardening.tpe_gid;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || req->newptr == NULL) {
		return (err);
	}

	if (pr == &prison0) {
		pax_tpe_gid = val;
	}

	pr->pr_hbsd.hardening.tpe_gid = val;

	return (0);
}

static int
sysctl_pax_tpe_negate(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);
	val = pr->pr_hbsd.hardening.tpe_negate;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || req->newptr == NULL) {
		return (err);
	}

	if (pr == &prison0) {
		pax_tpe_negate = val;
	}

	pr->pr_hbsd.hardening.tpe_negate = val;

	return (0);
}

static int
sysctl_pax_tpe_all(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);
	val = pr->pr_hbsd.hardening.tpe_all;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || req->newptr == NULL) {
		return (err);
	}

	if (pr == &prison0) {
		pax_tpe_all = val;
	}

	pr->pr_hbsd.hardening.tpe_all = val;

	return (0);
}

static int
sysctl_pax_tpe_root_owned(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);
	val = pr->pr_hbsd.hardening.tpe_root_owned;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || req->newptr == NULL) {
		return (err);
	}

	if (pr == &prison0) {
		pax_tpe_root_owned = val;
	}

	pr->pr_hbsd.hardening.tpe_root_owned = val;

	return (0);
}

static int
sysctl_pax_tpe_user_owned(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);
	val = pr->pr_hbsd.hardening.tpe_user_owned;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || req->newptr == NULL) {
		return (err);
	}

	if (pr == &prison0) {
		pax_tpe_user_owned = val;
	}

	pr->pr_hbsd.hardening.tpe_user_owned = val;

	return (0);
}
#endif /* PAX_SYSCTLS */
