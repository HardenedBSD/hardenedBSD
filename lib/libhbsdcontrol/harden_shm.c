/*-
 * Copyright (c) 2024 Shawn Webb <shawn.webb@hardenedbsd.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/extattr.h>

#include "libhbsdcontrol.h"

#define ATTRNAME_ENABLED	"hbsd.pax.harden_shm"
#define ATTRNAME_DISABLED	"hbsd.pax.noharden_shm"

static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_init(hbsdctrl_ctx_t *,
    hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_cleanup(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_pre_validate(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_validate(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_apply(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_unapply(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_get(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_harden_shm_help(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);

hbsdctrl_feature_t *
hbsdctrl_feature_harden_shm_new(hbsdctrl_ctx_t *ctx, hbsdctrl_flag_t flags)
{
	hbsdctrl_feature_t *feature;

	feature = hbsdctrl_feature_new(ctx, "harden_shm", flags);
	if (feature == NULL) {
		return (NULL);
	}

	hbsdctrl_feature_set_init(feature, hbsdctrl_feature_harden_shm_init);
	hbsdctrl_feature_set_cleanup(feature, hbsdctrl_feature_harden_shm_cleanup);
	hbsdctrl_feature_set_pre_validate(feature, hbsdctrl_feature_harden_shm_pre_validate);
	hbsdctrl_feature_set_validate(feature, hbsdctrl_feature_harden_shm_validate);
	hbsdctrl_feature_set_apply(feature, hbsdctrl_feature_harden_shm_apply);
	hbsdctrl_feature_set_unapply(feature, hbsdctrl_feature_harden_shm_unapply);
	hbsdctrl_feature_set_get(feature, hbsdctrl_feature_harden_shm_get);
	hbsdctrl_feature_set_help(feature, hbsdctrl_feature_harden_shm_help);

	return (feature);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_init(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_cleanup(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_pre_validate(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_validate(hbsdctrl_ctx_t *ctx, hbsdctrl_feature_t *feature,
    const void *arg1, void *arg2)
{
	hbsdctrl_feature_state_t state;
	hbsdctrl_feature_cb_res_t res;

	/*
	 * If arg2 is non-NULL, we are checking against an existing feature
	 * state object. Otherwise, we expect arg1 to be a pointer to a valid
	 * file descriptor and we fetch the current state from the underlying
	 * storage.
	 */

	if (arg1 == NULL && arg2 == NULL) {
		return (RES_FAIL);
	}

	if (arg2 == NULL) {
		memset(&state, 0, sizeof(state));
		res = feature->hf_get(ctx, feature, arg1, &state);
		if (res != RES_SUCCESS) {
			return (res);
		}

		arg2 = &state;
	}

	if (hbsdctrl_feature_state_value_valid(
	    hbsdctrl_feature_state_get_value(arg2)) == false) {
		return (RES_FAIL);
	}

	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_apply(hbsdctrl_ctx_t *ctx, hbsdctrl_feature_t *feature __unused,
    const void *arg1, void *arg2)
{
	hbsdctrl_feature_state_value_t value;
	hbsdctrl_feature_state_t *state;
	unsigned char buf[2];
	int fd;

	if (arg1 == NULL || arg2 == NULL) {
		return (RES_FAIL);
	}

	state = (hbsdctrl_feature_state_t *)arg2;
	fd = *(__DECONST(int *, arg1));

	if (fd < 0) {
		return (RES_FAIL);
	}

	value = hbsdctrl_feature_state_get_value(state);
	if (!hbsdctrl_feature_state_value_valid(value)) {
		return (RES_FAIL);
	}

	buf[0] = (value == HBSDCTRL_STATE_ENABLED) ? '1' : '0';
	if (extattr_set_fd(fd, ctx->hc_namespace, ATTRNAME_ENABLED, buf,
	    sizeof(buf)) != sizeof(buf)) {
		return (RES_FAIL);
	}

	buf[0] = (value == HBSDCTRL_STATE_DISABLED) ? '1' : '0';
	if (extattr_set_fd(fd, ctx->hc_namespace, ATTRNAME_DISABLED, buf,
	    sizeof(buf)) != sizeof(buf)) {
		return (RES_FAIL);
	}

	hbsdctrl_feature_state_set_flag(state, HBSDCTRL_FEATURE_STATE_FLAG_PERSISTED);

	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_unapply(hbsdctrl_ctx_t *ctx, hbsdctrl_feature_t *feature __unused,
    const void *arg1, void *arg2 __unused)
{
	int fd;

	if (arg1 == NULL) {
		return (RES_FAIL);
	}

	fd = *(__DECONST(int *, arg1));

	if (extattr_delete_fd(fd, ctx->hc_namespace, ATTRNAME_ENABLED)
	    && errno != ENOATTR) {
		return (RES_FAIL);
	}

	if (extattr_delete_fd(fd, ctx->hc_namespace, ATTRNAME_DISABLED)
	    && errno != ENOATTR) {
		return (RES_FAIL);
	}

	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_get(hbsdctrl_ctx_t *ctx, hbsdctrl_feature_t *feature __unused,
    const void *arg1, void *arg2)
{
	hbsdctrl_feature_state_t *res;
	bool enabled, disabled;
	unsigned char *buf;
	ssize_t sz;
	int fd;

	if (arg1 == NULL || arg2 == NULL) {
		return (RES_FAIL);
	}

	fd = *(int *)__DECONST(int *, arg1);
	res = (hbsdctrl_feature_state_t *)arg2;

	hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_SYSDEF);
	sz = extattr_get_fd(fd, ctx->hc_namespace, ATTRNAME_ENABLED, NULL, 0);
	if (sz <= 0) {
		if (errno == ENOATTR) {
			/*
			* This is okay, it just means that nothing has been set.
			* No error condition here.
			*/
			return (RES_SUCCESS);
		}
		return (RES_FAIL);
	}

	hbsdctrl_feature_state_set_flag(res, HBSDCTRL_FEATURE_STATE_FLAG_PERSISTED);

	if (sz > 2) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	buf = calloc(1, sz);
	if (buf == NULL) {
		return (RES_FAIL);
	}

	sz = extattr_get_fd(fd, ctx->hc_namespace, ATTRNAME_ENABLED, buf, sz);
	if (sz < 0) {
		free(buf);
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	enabled = buf[0] == '1';
	free(buf);

	sz = extattr_get_fd(fd, ctx->hc_namespace, ATTRNAME_DISABLED, NULL, 0);
	if (sz <= 0) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	if (sz > 2) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	buf = calloc(1, sz);
	if (buf == NULL) {
		return (RES_FAIL);
	}

	sz = extattr_get_fd(fd, ctx->hc_namespace, ATTRNAME_DISABLED, buf, sz);
	if (sz < 0) {
		free(buf);
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	disabled = buf[0] == '1';
	free(buf);

	if (enabled && disabled) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	if (enabled) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_ENABLED);
	} else {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_DISABLED);
	}

	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_harden_shm_help(hbsdctrl_ctx_t *ctx __unused,
    hbsdctrl_feature_t *feature __unused, const void *arg1 __unused,
    void *arg2)
{
	FILE *fp;

	fp = (arg2 == NULL) ? stderr : arg2;

	fprintf(fp, "harden_shm possible states:\n");
	fprintf(fp, "    1. enabled: force SHM hardening to be enabled\n");
	fprintf(fp, "    2. disabled: force SHM hardening to be disabled\n");
	fprintf(fp, "    3. sysdef: system default\n");

	return (RES_SUCCESS);
}
