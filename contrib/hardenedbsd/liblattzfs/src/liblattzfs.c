/*-
 * Copyright (c) 2021 Shawn Webb <shawn.webb@hardenedbsd.org>
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

#define __STDC_WANT_LIB_EXT1__ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdbool.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libzfs.h>
#include <libzfs_core.h>

#include "liblattzfs.h"

static bool _lattzfs_pool_open(lattzfs_ctx_t *);

lattzfs_ctx_t *
lattzfs_ctx_new(const char *pool, uint64_t flags)
{
	lattzfs_ctx_t *ctx;

	if (pool == NULL) {
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->lc_version = LATTZFS_VERSION;
	ctx->lc_pool_name = strdup(pool);
	if (ctx->lc_pool_name == NULL) {
		free(ctx);
		return (NULL);
	}

	ctx->lc_zfs_handle = libzfs_init();
	if (ctx->lc_zfs_handle == NULL) {
		free(ctx);
		free(ctx->lc_pool_name);
		return (NULL);
	}

	if (!(flags & LATTZFS_FLAG_LAZY_OPEN)) {
		if (!_lattzfs_pool_open(ctx)) {
			free(ctx->lc_pool_name);
			free(ctx);
			return (NULL);
		}
	}

	return (ctx);
}

void
lattzfs_ctx_free(lattzfs_ctx_t **ctx)
{
	lattzfs_ctx_t *ctxp;

	if (ctx == NULL || *ctx == NULL) {
		return;
	}

	ctxp = *ctx;

	if (ctxp->lc_pool_handle != NULL) {
		zpool_close(ctxp->lc_pool_handle);
	}

	if (ctxp->lc_zfs_handle != NULL) {
		zfs_close(ctxp->lc_zfs_handle);
	}

	free(ctxp->lc_pool_name);
	memset_s(ctxp, sizeof(*ctxp), 0, sizeof(*ctxp));
	free(ctxp);
	*ctx = NULL;
}

bool
lattzfs_zpool_get_status(lattzfs_ctx_t *ctx, lattzfs_zpool_status_t *status,
    lattzfs_zpool_errata_t *errata)
{
	zpool_errata_t zerrata;
	zpool_status_t zstatus;
	const char *msgid;

	if (ctx == NULL || status == NULL || errata == NULL) {
		return (false);
	}

	if (!_lattzfs_pool_open(ctx)) {
		return (false);
	}

	msgid = NULL;
	zerrata = 0;
	zstatus = zpool_get_status(ctx->lc_pool_handle, &msgid, &zerrata);

	*errata = (lattzfs_zpool_errata_t)zerrata;
	*status = (lattzfs_zpool_status_t)zstatus;

	return (true);
}

uint64_t
lattzfs_get_version(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (0);
	}

	return (ctx->lc_version);
}

uint64_t
lattzfs_get_flags(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (0);
	}

	return (ctx->lc_flags);
}

uint64_t
lattzfs_set_flags(lattzfs_ctx_t *ctx, uint64_t flags)
{
	uint64_t orig;

	if (ctx == NULL) {
		return (0);
	}

	orig = ctx->lc_flags;
	ctx->lc_flags = flags;
	return (orig);
}

uint64_t
lattzfs_set_flag(lattzfs_ctx_t *ctx, uint64_t flag)
{
	uint64_t orig;

	if (ctx == NULL) {
		return (0);
	}

	orig = ctx->lc_flags;
	ctx->lc_flags |= flag;
	return (orig);
}

void *
lattzfs_get_zfs_handle(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (NULL);
	}

	return (ctx->lc_zfs_handle);
}

void *
lattzfs_get_pool_handle(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (NULL);
	}

	return (ctx->lc_pool_handle);
}

char *
lattzfs_get_pool_name(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (NULL);
	}

	return (ctx->lc_pool_name);
}

static bool
_lattzfs_pool_open(lattzfs_ctx_t *ctx)
{

	if (ctx == NULL) {
		return (false);
	}

	if (ctx->lc_pool_handle != NULL) {
		return (true);
	}

	ctx->lc_pool_handle = zpool_open(ctx->lc_zfs_handle,
	    ctx->lc_pool_name);

	if (ctx->lc_pool_handle == NULL) {
		return (false);
	}

	return (true);
}
