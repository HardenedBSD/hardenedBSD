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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/queue.h>

#define LIBHBSDCONTROL_VERSION			20240316001UL
#define LIBHBSDCONTROL_DEFAULT_NAMESPACE	"system"

#define HBSDCTRL_FEATURE_STATE_FLAG_NONE	0x0UL
#define HBSDCTRL_FEATURE_STATE_FLAG_PERSISTED	0x1UL
#define HBSDCTRL_FEATURE_STATE_FLAG_ALL	(	\
    HBSDCTRL_FEATURE_STATE_FLAG_PERSISTED	\
)

typedef uint64_t hbsdctrl_flag_t;

struct _hbsdctrl_ctx;
struct _hbsdctrl_feature;
struct _hbsdctrl_feature_state;
struct _hbsdctrl_file_states_head;
struct _hbsdctrl_file_states;

typedef struct _hbsdctrl_ctx hbsdctrl_ctx_t;
typedef struct _hbsdctrl_feature hbsdctrl_feature_t;
typedef struct _hbsdctrl_feature_state hbsdctrl_feature_state_t;
typedef struct _hbsdctrl_file_states hbsdctrl_file_states_t;
typedef struct _hbsdctrl_file_states_head hbsdctrl_file_states_head_t;

typedef enum _hbsdctrl_feature_cb_res {
	RES_SUCCESS	= 0,
	RES_FAIL	= 1,
} hbsdctrl_feature_cb_res_t;

typedef enum _hbsdctrl_feature_state_value {
	HBSDCTRL_STATE_UNKNOWN	= 0,
	HBSDCTRL_STATE_ENABLED	= 1,
	HBSDCTRL_STATE_DISABLED	= 2,
	HBSDCTRL_STATE_SYSDEF	= 3,
	HBSDCTRL_STATE_INVALID	= 4,
} hbsdctrl_feature_state_value_t;

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
	int				 hc_namespace;
	pthread_mutex_t			 hc_mtx;
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
	hbsdctrl_feature_cb_t		 hf_get;
	hbsdctrl_feature_cb_t		 hf_help;
	hbsdctrl_ctx_t			*hf_ctx;
	void				*hf_data;
	LIST_ENTRY(_hbsdctrl_feature)	 hf_entry;
	uint64_t			 hf_spare[32];
};

struct _hbsdctrl_feature_state {
	hbsdctrl_feature_state_value_t	 hfs_value;
	hbsdctrl_flag_t			 hfs_flags;
	int				 hfs_fd;
	uint64_t			 hfs_spare[16];
};

struct _hbsdctrl_file_states_head {
	LIST_HEAD(,_hbsdctrl_file_states)	 hfsh_states;
};

struct _hbsdctrl_file_states {
	hbsdctrl_feature_t			*hfs_feature;
	hbsdctrl_feature_state_t		*hfs_state;
	hbsdctrl_feature_cb_res_t		 hfs_state_get_res;
	LIST_ENTRY(_hbsdctrl_file_states)	 hfs_entry;
};

uint64_t libhbsdctrl_get_version(void);

hbsdctrl_ctx_t *hbsdctrl_ctx_new(hbsdctrl_flag_t, const char *);
void hbsdctrl_ctx_free(hbsdctrl_ctx_t **);
bool hbsdctrl_ctx_check_flag_sanity(hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_ctx_get_flags(const hbsdctrl_ctx_t *);
hbsdctrl_flag_t hbsdctrl_ctx_set_flag(hbsdctrl_ctx_t *, hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_ctx_set_flags(hbsdctrl_ctx_t *, hbsdctrl_flag_t);
bool hbsdctrl_ctx_is_flag_set(const hbsdctrl_ctx_t *, hbsdctrl_flag_t);
bool hbsdctrl_ctx_add_feature(hbsdctrl_ctx_t *, hbsdctrl_feature_t *);
hbsdctrl_feature_t *hbsdctrl_ctx_find_feature_by_name(hbsdctrl_ctx_t *,
    const char *);
char **hbsdctrl_ctx_all_feature_names(hbsdctrl_ctx_t *);
void hbsdctrl_ctx_free_feature_names(char **);

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
void hbsdctrl_feature_set_get(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
void hbsdctrl_feature_set_help(hbsdctrl_feature_t *, hbsdctrl_feature_cb_t);
hbsdctrl_feature_cb_res_t hbsdctrl_feature_call_cb(hbsdctrl_feature_t *,
    const char *, const void *, void *);

hbsdctrl_feature_state_t *hbsdctrl_feature_state_new(int, hbsdctrl_flag_t);
void hbsdctrl_feature_state_free(hbsdctrl_feature_state_t **);
bool hbsdctrl_feature_state_value_valid(hbsdctrl_feature_state_value_t);
bool hbsdctrl_feature_state_set_value(hbsdctrl_feature_state_t *,
    hbsdctrl_feature_state_value_t);
hbsdctrl_feature_state_value_t hbsdctrl_feature_state_get_value(
    hbsdctrl_feature_state_t *);
const char *hbsdctrl_feature_state_to_string(hbsdctrl_feature_state_t *);
bool hbsdctrl_feature_state_flag_sanity(hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_feature_state_get_flags(hbsdctrl_feature_state_t *);
hbsdctrl_flag_t hbsdctrl_feature_state_set_flag(hbsdctrl_feature_state_t *,
    hbsdctrl_flag_t);
hbsdctrl_flag_t hbsdctrl_feature_state_set_flags(hbsdctrl_feature_state_t *,
    hbsdctrl_flag_t);
bool hbsdctrl_feature_state_is_flag_set(hbsdctrl_feature_state_t *,
    hbsdctrl_flag_t);

hbsdctrl_feature_cb_res_t hbsdctrl_exec_all_features(hbsdctrl_ctx_t *,
    const char *, bool, const void *, void *);

hbsdctrl_file_states_head_t *hbsdctrl_get_file_states(hbsdctrl_ctx_t *, int);
void hbsdctrl_free_file_states(hbsdctrl_file_states_head_t **);
hbsdctrl_feature_t *hbsdctrl_file_states_get_feature(hbsdctrl_file_states_t *);
hbsdctrl_feature_state_t *hbsdctrl_file_states_get_feature_state(
    hbsdctrl_file_states_t *);
hbsdctrl_feature_cb_res_t hbsdctrl_file_states_get_feature_state_res(
    hbsdctrl_file_states_t *);

/* aslr.c */
hbsdctrl_feature_t *hbsdctrl_feature_aslr_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

/* disallow_map32bit.c */
hbsdctrl_feature_t *hbsdctrl_feature_disallow_map32bit_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

/* pageexec.c */
hbsdctrl_feature_t *hbsdctrl_feature_pageexec_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

/* mprotect.c */
hbsdctrl_feature_t *hbsdctrl_feature_mprotect_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

/* segvguard.c */
hbsdctrl_feature_t *hbsdctrl_feature_segvguard_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

/* shlibrandom.c */
hbsdctrl_feature_t *hbsdctrl_feature_shlibrandom_new(hbsdctrl_ctx_t *,
    hbsdctrl_flag_t);

#endif /* !_LIBHBSDCONTROL_H */
