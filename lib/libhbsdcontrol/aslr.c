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

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/extattr.h>

#include "libhbsdcontrol.h"

typedef struct _aslr_state {
	bool	 as_enabled;
	bool	 as_disabled;
	bool	 as_set;
} aslr_state_t;

static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_init(hbsdctrl_ctx_t *,
    hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_cleanup(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_pre_validate(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_validate(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_apply(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_unapply(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);
static hbsdctrl_feature_cb_res_t hbsdctrl_feature_aslr_get(
    hbsdctrl_ctx_t *, hbsdctrl_feature_t *, const void *, void *);

static aslr_state_t *aslr_state_new(void);
static void aslr_state_free(aslr_state_t **);

hbsdctrl_feature_t *
hbsdctrl_feature_aslr_new(hbsdctrl_ctx_t *ctx, hbsdctrl_flag_t flags)
{
	hbsdctrl_feature_t *feature;

	feature = hbsdctrl_feature_new(ctx, "aslr", flags);
	if (feature == NULL) {
		return (NULL);
	}

	hbsdctrl_feature_set_init(feature, hbsdctrl_feature_aslr_init);
	hbsdctrl_feature_set_cleanup(feature, hbsdctrl_feature_aslr_cleanup);
	hbsdctrl_feature_set_pre_validate(feature, hbsdctrl_feature_aslr_pre_validate);
	hbsdctrl_feature_set_validate(feature, hbsdctrl_feature_aslr_validate);
	hbsdctrl_feature_set_apply(feature, hbsdctrl_feature_aslr_apply);
	hbsdctrl_feature_set_unapply(feature, hbsdctrl_feature_aslr_unapply);
	hbsdctrl_feature_set_get(feature, hbsdctrl_feature_aslr_get);

	return (feature);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_init(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	feature->hf_data = aslr_state_new();
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_cleanup(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	aslr_state_t *state;

	state = (aslr_state_t *)(feature->hf_data);
	aslr_state_free(&state);
	feature->hf_data = NULL;

	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_pre_validate(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_validate(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_apply(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_unapply(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1 __unused, void *arg2 __unused)
{
	return (RES_SUCCESS);
}

static hbsdctrl_feature_cb_res_t
hbsdctrl_feature_aslr_get(hbsdctrl_ctx_t *ctx __unused, hbsdctrl_feature_t *feature __unused,
    const void *arg1, void *arg2)
{
	hbsdctrl_feature_state_t *res;
	aslr_state_t *state;
	unsigned char *buf;
	ssize_t sz;
	int fd;

	if (arg1 == NULL || arg2 == NULL) {
		return (RES_FAIL);
	}

	state = (aslr_state_t *)(feature->hf_data);
	if (state == NULL) {
		state = aslr_state_new();
		if (state == NULL) {
			return (RES_FAIL);
		}
		feature->hf_data = state;
	}

	fd = *(int *)__DECONST(int *, arg1);
	res = (hbsdctrl_feature_state_t *)arg2;

	hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_SYSDEF);
	sz = extattr_get_fd(fd, ctx->hc_namespace, "hbsd.pax.aslr", NULL, 0);
	if (sz <= 0) {
		goto end;
	}

	if (sz > 2) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	buf = calloc(1, sz);
	if (buf == NULL) {
		return (RES_FAIL);
	}

	sz = extattr_get_fd(fd, ctx->hc_namespace, "hbsd.pax.aslr", buf, sz);
	if (sz < 0) {
		free(buf);
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	state->as_enabled = buf[0] == '1';
	free(buf);

	sz = extattr_get_fd(fd, ctx->hc_namespace, "hbsd.pax.noaslr", NULL, 0);
	if (sz <= 0) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		goto end;
	}

	if (sz > 2) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	buf = calloc(1, sz);
	if (buf == NULL) {
		return (RES_FAIL);
	}

	sz = extattr_get_fd(fd, ctx->hc_namespace, "hbsd.pax.noaslr", buf, sz);
	if (sz < 0) {
		free(buf);
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	state->as_disabled = buf[0] == '1';
	free(buf);

	if (state->as_enabled && state->as_disabled) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_INVALID);
		return (RES_FAIL);
	}

	if (state->as_enabled) {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_ENABLED);
	} else {
		hbsdctrl_feature_state_set_value(res, HBSDCTRL_STATE_DISABLED);
	}

end:
	return (RES_SUCCESS);
}

static aslr_state_t *
aslr_state_new(void)
{
	aslr_state_t *state;

	state = calloc(1, sizeof(*state));
	return (state);
}

static void
aslr_state_free(aslr_state_t **statep)
{
	aslr_state_t *state;

	if (statep == NULL || *statep == NULL) {
		return;
	}

	state = *statep;
	*statep = NULL;
	free(state);
}
