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

#ifndef _LIBHBSDCONTROL_H
#define _LIBHBSDCONTROL_H

#include <stdbool.h>
#include <stdint.h>

#include <sys/queue.h>

#define LIBHBSDCONTROL_VERSION	20240316001UL

typedef uint64_t hbsdctrl_flag_t;

struct _hbsdctrl_ctx;
struct _hbsdctrl_feature;

typedef struct _hbsdctrl_ctx hbsdctrl_ctx_t;
typedef struct _hbsdctrl_feature hbsdctrl_feature_t;

typedef enum _hbsdctrl_feature_cb_res {
	RES_SUCCESS	= 0,
	RES_FAIL	= 1,
} hbsdctrl_feature_cb_res_t;

/*
 * Each feature implements callbacks for various operations. Arguments:
 *     1. Pointer to the hbsdcontrol context object
 *     2. Pointer to the hbsdcontrol feature object
 *     3. Optional pointer to input variable
 *     4. Optional pointer to input/output variable
 * Arguments 3 and 4 are context-dependent and may be NULL. For example,
 * argument 3 for the hc_validate function pointer would be a pointer to the
 * value being validated.
 */
typedef hbsdctrl_feature_cb_res_t (*hbsdctrl_feature_cb_t)(hbsdctrl_ctx_t *,
    hbsdctrl_feature_t *, const void *, void *);

struct _hbsdctrl_ctx {
	uint64_t			 hc_version;
	hbsdctrl_flag_t			 hc_flags;
	LIST_HEAD(,_hbsdctrl_feature)	 hc_features;
	uint64_t			 hc_spare[32];
};

struct _hbsdctrl_feature {
	hbsdctrl_flag_t			 hf_flags;
	char				*hf_name;
	hbsdctrl_feature_cb_t		 hf_init;
	hbsdctrl_feature_cb_t		 hf_cleanup;
	hbsdctrl_feature_cb_t		 hf_pre_validate;
	hbsdctrl_feature_cb_t		 hf_validate;
	hbsdctrl_feature_cb_t		 hf_apply;
	hbsdctrl_feature_cb_t		 hf_unapply;
	hbsdctrl_ctx_t			*hf_ctx;
	void				*hf_data;
	LIST_ENTRY(_hbsdctrl_feature)	 hf_entry;
	uint64_t			 hf_spare[32];
};

uint64_t libhbsdctrl_get_version(void);

hbsdctrl_ctx_t *hbsdctrl_ctx_new(hbsdctrl_flag_t);
void hbsdctrl_ctx_free(hbsdctrl_ctx_t **);
bool hbsdctrl_ctx_check_flag_sanity(hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_ctx_get_flags(const hbsdctrl_ctx_t *);
hbsdctrl_flag_t hbsdctrl_ctx_set_flag(hbsdctrl_ctx_t *, hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_ctx_set_flags(hbsdctrl_ctx_t *, hbsdctrl_flag_t);
bool hbsdctrl_ctx_is_flag_set(const hbsdctrl_ctx_t *, hbsdctrl_flag_t);

hbsdctrl_feature_t *hbsdctrl_feature_new(hbsdctrl_ctx_t *, const char *, hbsdctrl_flag_t);
void hbsdctrl_feature_free(hbsdctrl_feature_t **);
bool hbsdctrl_feature_flag_sanity(hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_feature_get_flags(const hbsdctrl_feature_t *);
hbsdctrl_flag_t hbsdctrl_feature_set_flag(hbsdctrl_feature_t *, hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_feature_set_flags(hbsdctrl_feature_t *, hbsdctrl_flag_t);
bool hbsdctrl_feature_is_flag_set(const hbsdctrl_feature_t *, hbsdctrl_flag_t);

const char *hbsdctrl_feature_get_name(const hbsdctrl_feature_t *);
void *hbsdctrl_feature_get_data(const hbsdctrl_feature_t *);
void *hbsdctrl_feature_set_data(hbsdctrl_feature_t *, void *);

void hbsdctrl_feature_set_init(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_cleanup(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_pre_validate(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_validate(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_apply(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_unapply(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
hbsdctrl_feature_cb_res_t hbsdctrl_feature_call_cb(hbsdctrl_feature_t *,
    const char *, const void *, void *);

#endif /* !_LIBHBSDCONTROL_H */
