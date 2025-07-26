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

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);
SYSCTL_NODE(_hardening_pax, OID_AUTO, tpe, CTLFLAG_RD, 0,
    "Settings for Trusted Path Execution (TPE).");

SYSCTL_HBSD_4STATE(pax_tpe_global, pr_hbsd.hardening.tpe,
    _hardening_pax_tpe, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);
SYSCTL_INT(_hardening_pax_tpe, OID_AUTO, gid,
    CTLFLAG_RWTUN|CTLFLAG_SECURE, &pax_tpe_gid, 0,
    "Untrusted TPE GID");
SYSCTL_INT(_hardening_pax_tpe, OID_AUTO, negate,
    CTLFLAG_RWTUN|CTLFLAG_SECURE, &pax_tpe_negate, 0,
    "Negate TPE GID logic");
SYSCTL_INT(_hardening_pax_tpe, OID_AUTO, all,
    CTLFLAG_RWTUN|CTLFLAG_SECURE, &pax_tpe_all, 0,
    "Apply TPE to all users");
SYSCTL_INT(_hardening_pax_tpe, OID_AUTO, root_owned,
    CTLFLAG_RWTUN|CTLFLAG_SECURE, &pax_tpe_root_owned, 0,
    "Ensure directory is root-owned");
SYSCTL_INT(_hardening_pax_tpe, OID_AUTO, user_owned,
    CTLFLAG_RWTUN|CTLFLAG_SECURE, &pax_tpe_user_owned, 0,
    "Ensure directory is user-owned");
#endif

static bool _pax_tpe_active(struct thread *);

int
pax_tpe_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;

	if (pr == &prison0) {
		pr->pr_hbsd.hardening.tpe = pax_tpe_global;
	} else {
		pr_p = pr->pr_parent;
		pr->pr_hbsd.hardening.tpe = pr_p->pr_hbsd.hardening.tpe;
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

	memset(&nd, 0, sizeof(nd));
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, parent_path);
	nd.ni_debugflags |= NAMEI_DBG_INITED;
	error = namei(&nd);
	if (error) {
		free(parent_path, M_TEMP);
		NDFREE_PNBUF(&nd);
		return (error);
	}

	error = VOP_GETATTR(nd.ni_vp, &vap, td->td_ucred);
	if (error) {
		goto end;
	}

	if (pax_tpe_root_owned) {
		if (vap.va_uid != 0) {
			error = EPERM;
			goto end;
		}
	}

	if (pax_tpe_user_owned && td->td_ucred->cr_uid != 0) {
		if (vap.va_uid != 0 && vap.va_uid != td->td_ucred->cr_uid) {
			error = EPERM;
			goto end;
		}
	}

	if ((vap.va_mode & (S_IWGRP | S_IWOTH)) != 0) {
		error = EPERM;
		goto end;
	}

end:
	NDFREE_PNBUF(&nd);
	free(parent_path, M_TEMP);
	return (error);
}

static bool
_pax_tpe_active(struct thread *td)
{
	pax_flag_t flags;

	pax_get_flags(td->td_proc, &flags);
	if ((flags & PAX_NOTE_NOTPE) == PAX_NOTE_NOTPE) {
		return (false);
	}

	if (pax_tpe_all) {
		return (true);
	}

	if (td->td_ucred->cr_gid == pax_tpe_gid) {
		return (pax_tpe_negate == 0);
	}

	return (pax_tpe_negate != 0);
}
