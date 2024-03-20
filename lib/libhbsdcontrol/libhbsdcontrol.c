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
#include <libutil.h>

#include "libhbsdcontrol.h"

uint64_t
libhbsdctrl_get_version(void)
{
	return (LIBHBSDCONTROL_VERSION);
}

hbsdctrl_ctx_t *
hbsdctrl_ctx_new(hbsdctrl_flag_t flags, const char *ns)
{
	hbsdctrl_feature_t *feature;
	hbsdctrl_ctx_t *ctx;

	if (!hbsdctrl_ctx_check_flag_sanity(flags)) {
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->hc_namespace = -1;
	if (extattr_string_to_namespace(ns, &(ctx->hc_namespace))) {
		free(ctx);
		return (NULL);
	}

	memset(&(ctx->hc_mtx), 0, sizeof(ctx->hc_mtx));
	if (pthread_mutex_init(&(ctx->hc_mtx), NULL)) {
		free(ctx);
		return (NULL);
	}

	ctx->hc_version = LIBHBSDCONTROL_VERSION;
	ctx->hc_flags = flags;

	LIST_INIT(&(ctx->hc_features));

	feature = hbsdctrl_feature_aslr_new(ctx, 0);
	if (feature == NULL) {
		hbsdctrl_ctx_free(&ctx);
		return (NULL);
	}
	if (!hbsdctrl_ctx_add_feature(ctx, feature)) {
		hbsdctrl_ctx_free(&ctx);
		return (NULL);
	}

	feature = hbsdctrl_feature_pageexec_new(ctx, 0);
	if (feature == NULL) {
		hbsdctrl_ctx_free(&ctx);
		return (NULL);
	}
	if (!hbsdctrl_ctx_add_feature(ctx, feature)) {
		hbsdctrl_ctx_free(&ctx);
		return (NULL);
	}

	return (ctx);
}

void
hbsdctrl_ctx_free(hbsdctrl_ctx_t **ctxp)
{
	hbsdctrl_feature_t *feature, *tfeature;
	hbsdctrl_ctx_t *ctx;

	if (ctxp == NULL || *ctxp == NULL) {
		return;
	}

	ctx = *ctxp;
	*ctxp = NULL;

	pthread_mutex_lock(&(ctx->hc_mtx));
	LIST_FOREACH_SAFE(feature, &(ctx->hc_features), hf_entry, tfeature) {
		LIST_REMOVE(feature, hf_entry);
		hbsdctrl_feature_free(&feature);
	}
	pthread_mutex_unlock(&(ctx->hc_mtx));
	pthread_mutex_destroy(&(ctx->hc_mtx));

	free(ctx);
}

bool
hbsdctrl_ctx_check_flag_sanity(hbsdctrl_flag_t flags)
{
	/* No flags supported, yet */
	return (flags == 0);
}

hbsdctrl_flag_t
hbsdctrl_ctx_get_flags(const hbsdctrl_ctx_t *ctx)
{
	if (ctx == NULL) {
		return (0);
	}

	return (ctx->hc_flags);
}

hbsdctrl_flag_t
hbsdctrl_ctx_set_flag(hbsdctrl_ctx_t *ctx, hbsdctrl_flag_t flag)
{
	hbsdctrl_flag_t oldflags;

	if (ctx == NULL) {
		return (0);
	}

	if (!hbsdctrl_ctx_check_flag_sanity(ctx->hc_flags | flag)) {
		return (ctx->hc_flags);
	}

	oldflags = ctx->hc_flags;
	ctx->hc_flags |= flag;
	return (oldflags);
}

hbsdctrl_flag_t
hbsdctrl_ctx_set_flags(hbsdctrl_ctx_t *ctx, hbsdctrl_flag_t flags)
{
	hbsdctrl_flag_t oldflags;

	if (ctx == NULL) {
		return (0);
	}

	if (!hbsdctrl_ctx_check_flag_sanity(flags)) {
		return (ctx->hc_flags);
	}

	oldflags = ctx->hc_flags;
	ctx->hc_flags = flags;
	return (oldflags);
}

bool
hbsdctrl_ctx_is_flag_set(const hbsdctrl_ctx_t *ctx, hbsdctrl_flag_t flag)
{
	if (ctx == NULL) {
		return (false);
	}

	return ((ctx->hc_flags & flag) == flag);
}

bool
hbsdctrl_ctx_add_feature(hbsdctrl_ctx_t *ctx, hbsdctrl_feature_t *feature)
{
	if (ctx == NULL || feature == NULL) {
		return (false);
	}

	/* feature->hf_ctx gets set when creating a new feature object */
	if (feature->hf_ctx != ctx) {
		return (false);
	}

	if (hbsdctrl_ctx_find_feature_by_name(ctx, feature->hf_name) != NULL) {
		return (false);
	}

	pthread_mutex_lock(&(ctx->hc_mtx));
	LIST_INSERT_HEAD(&(ctx->hc_features), feature, hf_entry);
	pthread_mutex_unlock(&(ctx->hc_mtx));
	return (true);
}

hbsdctrl_feature_t *
hbsdctrl_ctx_find_feature_by_name(hbsdctrl_ctx_t *ctx, const char *name)
{
	hbsdctrl_feature_t *feature, *tfeature;

	if (ctx == NULL || name == NULL) {
		return (NULL);
	}

	pthread_mutex_lock(&(ctx->hc_mtx));
	LIST_FOREACH_SAFE(feature, &(ctx->hc_features), hf_entry, tfeature) {
		if (feature->hf_name == NULL) {
			continue;
		}

		if (!strcasecmp(feature->hf_name, name)) {
			break;
		}
	}
	pthread_mutex_unlock(&(ctx->hc_mtx));

	return (feature);
}

char **
hbsdctrl_ctx_all_feature_names(hbsdctrl_ctx_t *ctx)
{
	hbsdctrl_feature_t *feature, *tfeature;
	size_t i, nres;
	char **res;

	if (ctx == NULL) {
		return (NULL);
	}

	nres = 1; /* 1 for the terminating NULL entry */
	pthread_mutex_lock(&(ctx->hc_mtx));
	LIST_FOREACH_SAFE(feature, &(ctx->hc_features), hf_entry, tfeature) {
		nres++;
	}

	res = calloc(nres, sizeof(char **));
	if (res == NULL) {
		goto end;
	}

	i = 0;
	LIST_FOREACH_SAFE(feature, &(ctx->hc_features), hf_entry, tfeature) {
		res[i++] = feature->hf_name;
	}

end:
	pthread_mutex_unlock(&(ctx->hc_mtx));
	return (res);
}

void
hbsdctrl_ctx_free_feature_names(char **names)
{
	free(names);
}

hbsdctrl_feature_t *
hbsdctrl_feature_new(hbsdctrl_ctx_t *ctx, const char *name, hbsdctrl_flag_t flags)
{
	hbsdctrl_feature_t *feature;

	if (ctx == NULL || name == NULL) {
		return (NULL);
	}

	feature = calloc(1, sizeof(*feature));
	if (feature == NULL) {
		return (NULL);
	}

	feature->hf_name = strdup(name);
	if (feature->hf_name == NULL) {
		free(feature);
		return (NULL);
	}

	feature->hf_ctx = ctx;
	feature->hf_flags = flags;

	return (feature);
}

void
hbsdctrl_feature_free(hbsdctrl_feature_t **featurep)
{
	hbsdctrl_feature_t *feature;

	if (featurep == NULL || *featurep == NULL) {
		return;
	}

	feature = *featurep;
	*featurep = NULL;
	free(feature->hf_name);
	free(feature);
}

bool
hbsdctrl_feature_flag_sanity(hbsdctrl_flag_t flag)
{
	/* No flags supported, yet */
	return (flag == 0);
}

hbsdctrl_flag_t
hbsdctrl_feature_get_flags(const hbsdctrl_feature_t *feature)
{
	if (feature == NULL) {
		return (0);
	}

	return (feature->hf_flags);
}

hbsdctrl_flag_t
hbsdctrl_feature_set_flag(hbsdctrl_feature_t *feature, hbsdctrl_flag_t flag)
{
	hbsdctrl_flag_t oldflags;

	if (feature == NULL) {
		return (0);
	}

	if (!hbsdctrl_feature_flag_sanity(feature->hf_flags | flag)) {
		return (feature->hf_flags);
	}

	oldflags = feature->hf_flags;
	feature->hf_flags |= flag;
	return (oldflags);
}

hbsdctrl_flag_t
hbsdctrl_feature_set_flags(hbsdctrl_feature_t *feature, hbsdctrl_flag_t flags)
{
	hbsdctrl_flag_t oldflags;

	if (feature == NULL) {
		return (0);
	}

	if (!hbsdctrl_feature_flag_sanity(flags)) {
		return (feature->hf_flags);
	}

	oldflags = feature->hf_flags;
	feature->hf_flags = flags;
	return (oldflags);
}

bool
hbsdctrl_feature_is_flag_set(const hbsdctrl_feature_t *feature, hbsdctrl_flag_t flag)
{
	if (feature == NULL) {
		return (false);
	}

	return ((feature->hf_flags & flag) == flag);
}

const char *
hbsdctrl_feature_get_name(const hbsdctrl_feature_t *feature)
{
	if (feature == NULL) {
		return (NULL);
	}

	return ((const char *)(feature->hf_name));
}

void *
hbsdctrl_feature_get_data(const hbsdctrl_feature_t *feature)
{
	if (feature == NULL) {
		return (NULL);
	}

	return (feature->hf_data);
}

void *
hbsdctrl_feature_set_data(hbsdctrl_feature_t *feature, void *data)
{
	void *olddata;

	if (feature == NULL) {
		return (NULL);
	}

	olddata = feature->hf_data;
	feature->hf_data = data;
	return (olddata);
}

void
hbsdctrl_feature_set_init(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_init = cb;
}

void
hbsdctrl_feature_set_cleanup(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_cleanup = cb;
}

void
hbsdctrl_feature_set_pre_validate(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_pre_validate = cb;
}

void
hbsdctrl_feature_set_validate(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_validate = cb;
}

void
hbsdctrl_feature_set_apply(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_apply = cb;
}

void
hbsdctrl_feature_set_unapply(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_unapply = cb;
}

void
hbsdctrl_feature_set_get(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_get = cb;
}

void
hbsdctrl_feature_set_help(hbsdctrl_feature_t *feature, hbsdctrl_feature_cb_t cb)
{
	if (feature == NULL) {
		return;
	}

	feature->hf_help = cb;
}

hbsdctrl_feature_cb_res_t
hbsdctrl_feature_call_cb(hbsdctrl_feature_t *feature, const char *name,
    const void *arg1, void *arg2)
{
	if (feature == NULL || name == NULL) {
		return (RES_FAIL);
	}

	if (!strcasecmp(name, "init") && feature->hf_init != NULL) {
		return (feature->hf_init(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "cleanup")) {
		if (feature->hf_cleanup == NULL) {
			return (RES_SUCCESS);
		}
		return (feature->hf_cleanup(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "prevalidate")) {
		if (feature->hf_pre_validate == NULL) {
			return (RES_SUCCESS);
		}
		return (feature->hf_pre_validate(feature->hf_ctx, feature,
		    arg1, arg2));
	}
	if (!strcasecmp(name, "validate")) {
		if (feature->hf_validate == NULL) {
			return (RES_SUCCESS);
		}
		return (feature->hf_validate(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "apply") && feature->hf_apply != NULL) {
		return (feature->hf_apply(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "unapply") && feature->hf_unapply != NULL) {
		return (feature->hf_unapply(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "get") && feature->hf_get != NULL) {
		return (feature->hf_get(feature->hf_ctx, feature, arg1,
		    arg2));
	}
	if (!strcasecmp(name, "help")) {
		if (feature->hf_help == NULL) {
			return (RES_SUCCESS);
		}
		return (feature->hf_help(feature->hf_ctx, feature, arg1,
		    arg2));
	}

	return (RES_FAIL);
}

hbsdctrl_feature_state_t *
hbsdctrl_feature_state_new(int fd, hbsdctrl_flag_t flags)
{
	hbsdctrl_feature_state_t *state;

	state = calloc(1, sizeof(*state));
	if (state == NULL) {
		return (NULL);
	}

	state->hfs_fd = fd;
	state->hfs_flags = flags;

	return (state);
}

void
hbsdctrl_feature_state_free(hbsdctrl_feature_state_t **statep)
{
	hbsdctrl_feature_state_t *state;

	if (statep == NULL || *statep == NULL) {
		return;
	}

	state = *statep;
	*statep = NULL;
	free(state);
}

bool
hbsdctrl_feature_state_value_valid(hbsdctrl_feature_state_value_t value)
{
	switch (value) {
	case HBSDCTRL_STATE_UNKNOWN:
	case HBSDCTRL_STATE_ENABLED:
	case HBSDCTRL_STATE_DISABLED:
	case HBSDCTRL_STATE_SYSDEF:
	case HBSDCTRL_STATE_INVALID:
		return (true);
	default:
		return (false);
	}
}

bool
hbsdctrl_feature_state_set_value(hbsdctrl_feature_state_t *state,
    hbsdctrl_feature_state_value_t value)
{
	if (state == NULL) {
		return (false);
	}

	state->hfs_value = value;
	return (true);
}

hbsdctrl_feature_state_value_t
hbsdctrl_feature_state_get_value(hbsdctrl_feature_state_t *state)
{
	if (state == NULL) {
		return (HBSDCTRL_STATE_UNKNOWN);
	}

	return (state->hfs_value);
}

const char *
hbsdctrl_feature_state_to_string(hbsdctrl_feature_state_t *state)
{
	if (state == NULL) {
		return (NULL);
	}

	switch (state->hfs_value) {
	case HBSDCTRL_STATE_ENABLED:
		return ("enabled");
	case HBSDCTRL_STATE_DISABLED:
		return ("disabled");
	case HBSDCTRL_STATE_SYSDEF:
		return ("sysdef");
	case HBSDCTRL_STATE_INVALID:
		return ("invalid");
	default:
		return ("unknown");
	}
}

bool
hbsdctrl_feature_state_flag_sanity(hbsdctrl_flag_t flag)
{
	return ((flag & ~(HBSDCTRL_FEATURE_STATE_FLAG_ALL)) == 0);
}

hbsdctrl_flag_t
hbsdctrl_feature_state_get_flags(hbsdctrl_feature_state_t *state)
{
	if (state == NULL) {
		return (0);
	}

	return (state->hfs_flags);
}

hbsdctrl_flag_t
hbsdctrl_feature_state_set_flag(hbsdctrl_feature_state_t *state,
    hbsdctrl_flag_t flag)
{
	hbsdctrl_flag_t oldflags;

	if (state == NULL) {
		return (0);
	}

	if (!hbsdctrl_feature_state_flag_sanity(state->hfs_flags | flag)) {
		return (state->hfs_flags);
	}

	oldflags = state->hfs_flags;
	state->hfs_flags |= flag;
	return (oldflags);
}

hbsdctrl_flag_t
hbsdctrl_feature_state_set_flags(hbsdctrl_feature_state_t *state,
    hbsdctrl_flag_t flags)
{
	hbsdctrl_flag_t oldflags;

	if (state == NULL) {
		return (0);
	}

	if (!hbsdctrl_feature_state_flag_sanity(flags)) {
		return (state->hfs_flags);
	}

	oldflags = state->hfs_flags;
	state->hfs_flags = flags;
	return (oldflags);
}

bool
hbsdctrl_feature_state_is_flag_set(hbsdctrl_feature_state_t *state,
    hbsdctrl_flag_t flag)
{
	if (state == NULL) {
		return (false);
	}

	return ((state->hfs_flags & flag) == flag);
}

hbsdctrl_feature_cb_res_t
hbsdctrl_exec_all_features(hbsdctrl_ctx_t *ctx, const char *cbname,
    bool bail_on_error, const void *arg1, void *arg2)
{
	hbsdctrl_feature_t *feature, *tfeature;
	hbsdctrl_feature_cb_res_t res, ret;

	res = RES_SUCCESS;
	ret = RES_SUCCESS;
	pthread_mutex_lock(&(ctx->hc_mtx));
	LIST_FOREACH_SAFE(feature, &(ctx->hc_features), hf_entry, tfeature) {
		res = hbsdctrl_feature_call_cb(feature, cbname, arg1, arg2);
		if (res != RES_SUCCESS) {
			if (bail_on_error) {
				ret = res;
				break;
			}

			ret = res;
		}
	}

	pthread_mutex_unlock(&(ctx->hc_mtx));
	return (ret);
}
