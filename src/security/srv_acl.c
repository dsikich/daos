/*
 * (C) Copyright 2019 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. 8F-30005.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

#include <unistd.h>
#include <string.h>
#include <daos_errno.h>
#include <daos/drpc.h>
#include <daos/drpc.pb-c.h>
#include <daos/drpc_modules.h>

#include <daos_srv/pool.h>
#include <daos_srv/security.h>

#include "auth.pb-c.h"
#include "srv_internal.h"

/**
 * The default ACLs for pool and container both include ACEs for owner and the
 * assigned group. All others are denied by default.
 */
#define NUM_DEFAULT_ACES	(2)

static struct daos_ace *
alloc_ace_with_access(enum daos_acl_principal_type type, uint64_t permissions)
{
	struct daos_ace *ace;

	ace = daos_ace_create(type, NULL);
	if (ace == NULL) {
		D_ERROR("Failed to allocate default ACE type %d", type);
		return NULL;
	}

	ace->dae_access_types = DAOS_ACL_ACCESS_ALLOW;
	ace->dae_allow_perms = permissions;

	return ace;
}

static struct daos_acl *
alloc_default_daos_acl_with_perms(uint64_t owner_perms,
				  uint64_t owner_grp_perms)
{
	int		i;
	struct daos_ace	*default_aces[NUM_DEFAULT_ACES];
	struct daos_acl	*default_acl;

	default_aces[0] = alloc_ace_with_access(DAOS_ACL_OWNER, owner_perms);
	default_aces[1] = alloc_ace_with_access(DAOS_ACL_OWNER_GROUP,
						owner_grp_perms);

	default_acl = daos_acl_create(default_aces, NUM_DEFAULT_ACES);

	for (i = 0; i < NUM_DEFAULT_ACES; i++) {
		daos_ace_free(default_aces[i]);
	}

	return default_acl;
}

struct daos_acl *
ds_sec_alloc_default_daos_cont_acl(void)
{
	struct daos_acl	*acl;
	uint64_t	owner_perms;
	uint64_t	grp_perms;

	/* container owner has full control */
	owner_perms = DAOS_ACL_PERM_CONT_ALL;
	/* owner-group has basic read/write access but not admin access */
	grp_perms = DAOS_ACL_PERM_READ | DAOS_ACL_PERM_WRITE |
		    DAOS_ACL_PERM_GET_PROP | DAOS_ACL_PERM_SET_PROP;

	acl = alloc_default_daos_acl_with_perms(owner_perms, grp_perms);
	if (acl == NULL)
		D_ERROR("Failed to allocate default ACL for cont properties");

	return acl;
}

struct daos_acl *
ds_sec_alloc_default_daos_pool_acl(void)
{
	struct daos_acl	*acl;
	uint64_t	owner_perms;
	uint64_t	grp_perms;

	/* pool owner and grp have full read/write access */
	owner_perms = DAOS_ACL_PERM_READ | DAOS_ACL_PERM_WRITE;
	grp_perms = DAOS_ACL_PERM_READ | DAOS_ACL_PERM_WRITE;

	acl = alloc_default_daos_acl_with_perms(owner_perms, grp_perms);
	if (acl == NULL)
		D_ERROR("Failed to allocate default ACL for pool properties");

	return acl;
}

static Auth__Token *
auth_token_dup(Auth__Token *orig)
{
	Auth__Token	*copy;
	uint8_t		*packed;
	size_t		len;

	/*
	 * The most straightforward way to copy a protobuf struct is to pack
	 * and unpack it.
	 */
	len = auth__token__get_packed_size(orig);
	D_ALLOC(packed, len);
	if (packed == NULL)
		return NULL;

	auth__token__pack(orig, packed);
	copy = auth__token__unpack(NULL, len, packed);
	D_FREE(packed);
	return copy;
}

static int
get_token_from_validation_response(Drpc__Response *response,
				   Auth__Token **token)
{
	Auth__ValidateCredResp	*resp;
	int			rc = 0;

	resp = auth__validate_cred_resp__unpack(NULL, response->body.len,
						response->body.data);
	if (resp == NULL) {
		D_ERROR("Response body was not a ValidateCredResp\n");
		return -DER_PROTO;
	}

	if (resp->status != 0) {
		D_ERROR("Response reported failed status: %d\n", resp->status);
		D_GOTO(out, rc = resp->status);
	}

	if (resp->token == NULL || resp->token->data.data == NULL) {
		D_ERROR("Response missing a valid auth token\n");
		D_GOTO(out, rc = -DER_PROTO);
	}

	*token = auth_token_dup(resp->token);
	if (*token == NULL) {
		D_ERROR("Couldn't copy the Auth Token\n");
		D_GOTO(out, rc = -DER_NOMEM);
	}

out:
	auth__validate_cred_resp__free_unpacked(resp, NULL);
	return rc;
}

static Drpc__Call *
new_validation_request(struct drpc *ctx, d_iov_t *creds)
{
	uint8_t			*body;
	size_t			len;
	Drpc__Call		*request;
	Auth__ValidateCredReq	req = AUTH__VALIDATE_CRED_REQ__INIT;
	Auth__Credential	*cred;

	request = drpc_call_create(ctx,
			DRPC_MODULE_SEC,
			DRPC_METHOD_SEC_VALIDATE_CREDS);
	if (request == NULL)
		return NULL;

	cred = auth__credential__unpack(NULL, creds->iov_buf_len,
					creds->iov_buf);
	if (cred == NULL) {
		drpc_call_free(request);
		return NULL;
	}
	req.cred = cred;

	len = auth__validate_cred_req__get_packed_size(&req);
	D_ALLOC(body, len);
	if (body == NULL) {
		drpc_call_free(request);
		auth__credential__free_unpacked(cred, NULL);
		return NULL;
	}
	auth__validate_cred_req__pack(&req, body);
	request->body.len = len;
	request->body.data = body;

	auth__credential__free_unpacked(cred, NULL);
	return request;
}

static int
validate_credentials_via_drpc(Drpc__Response **response, d_iov_t *creds)
{
	struct drpc	*server_socket;
	Drpc__Call	*request;
	int		rc;

	server_socket = drpc_connect(ds_sec_server_socket_path);
	if (server_socket == NULL) {
		D_ERROR("Couldn't connect to daos_server socket\n");
		return -DER_BADPATH;
	}

	request = new_validation_request(server_socket, creds);
	if (request == NULL) {
		return -DER_NOMEM;
	}

	rc = drpc_call(server_socket, R_SYNC, request, response);

	drpc_close(server_socket);
	drpc_call_free(request);
	return rc;
}

static int
process_validation_response(Drpc__Response *response, Auth__Token **token)
{
	if (response == NULL) {
		D_ERROR("Response was NULL\n");
		return -DER_NOREPLY;
	}

	if (response->status != DRPC__STATUS__SUCCESS) {
		D_ERROR("dRPC response error: %d\n", response->status);
		return -DER_MISC;
	}

	return get_token_from_validation_response(response, token);
}

int
ds_sec_validate_credentials(d_iov_t *creds, Auth__Token **token)
{
	Drpc__Response	*response = NULL;
	int		rc;

	if (creds == NULL ||
	    token == NULL ||
	    creds->iov_buf_len == 0 ||
	    creds->iov_buf == NULL) {
		D_ERROR("Credential iov invalid\n");
		return -DER_INVAL;
	}

	rc = validate_credentials_via_drpc(&response, creds);
	if (rc != DER_SUCCESS) {
		return rc;
	}

	rc = process_validation_response(response, token);

	drpc_response_free(response);
	return rc;
}

static uint64_t
pool_capas_from_perms(uint64_t perms)
{
	uint64_t capas = 0;

	if (perms & DAOS_ACL_PERM_READ)
		capas |= POOL_CAPA_READ;
	if ((perms & DAOS_ACL_PERM_WRITE) ||
	    (perms & DAOS_ACL_PERM_CREATE_CONT))
		capas |= POOL_CAPA_CREATE_CONT;
	if ((perms & DAOS_ACL_PERM_WRITE) ||
	    (perms & DAOS_ACL_PERM_DEL_CONT))
		capas |= POOL_CAPA_DEL_CONT;

	return capas;
}

static int
get_capas_for_principal(struct daos_acl *acl, enum daos_acl_principal_type type,
			const char *name, uint64_t *capas)
{
	struct daos_ace *ace;
	int		rc;

	D_DEBUG(DB_MGMT, "Checking ACE for principal type %d\n", type);

	rc = daos_acl_get_ace_for_principal(acl, type, name, &ace);
	if (rc != 0)
		return rc;

	*capas = pool_capas_from_perms(ace->dae_allow_perms);
	return 0;
}

static bool
authsys_has_group(const char *group, Auth__Sys *authsys)
{
	size_t i;

	if (strncmp(authsys->group, group,
		    DAOS_ACL_MAX_PRINCIPAL_LEN) == 0)
		return true;

	for (i = 0; i < authsys->n_groups; i++) {
		if (strncmp(authsys->groups[i], group,
			    DAOS_ACL_MAX_PRINCIPAL_LEN) == 0)
			return true;
	}

	return false;
}

static int
add_perms_for_principal(struct daos_acl *acl, enum daos_acl_principal_type type,
			const char *name, uint64_t *perms)
{
	int		rc;
	struct daos_ace	*ace = NULL;

	rc = daos_acl_get_ace_for_principal(acl, type, name, &ace);
	if (rc == 0)
		*perms |= ace->dae_allow_perms;

	return rc;
}

static int
get_capas_for_groups(struct daos_acl *acl,
		     struct ownership *ownership,
		     Auth__Sys *authsys, uint64_t *capas)
{
	int		rc;
	int		i;
	uint64_t	grp_perms = 0;
	bool		found = false;

	/*
	 * Group permissions are a union of the permissions of all groups the
	 * user is a member of, including the owner group.
	 */
	if (authsys_has_group(ownership->group, authsys)) {
		rc = add_perms_for_principal(acl, DAOS_ACL_OWNER_GROUP, NULL,
					     &grp_perms);
		if (rc == 0)
			found = true;
	}

	rc = add_perms_for_principal(acl, DAOS_ACL_GROUP, authsys->group,
				     &grp_perms);
	if (rc == 0)
		found = true;

	for (i = 0; i < authsys->n_groups; i++) {
		rc = add_perms_for_principal(acl, DAOS_ACL_GROUP,
					     authsys->groups[i], &grp_perms);
		if (rc == 0)
			found = true;
	}

	if (found) {
		*capas = pool_capas_from_perms(grp_perms);
		return 0;
	}

	return -DER_NONEXIST;
}

static int
get_authsys_capas(struct daos_acl *acl,
		  struct ownership *ownership,
		  Auth__Sys *authsys, uint64_t *capas)
{
	int rc;

	/* If this is the owner, and there's an owner entry... */
	if (strncmp(authsys->user, ownership->user,
		    DAOS_ACL_MAX_PRINCIPAL_LEN) == 0) {
		rc = get_capas_for_principal(acl, DAOS_ACL_OWNER, NULL,
					     capas);
		if (rc != -DER_NONEXIST)
			return rc;
	}

	/* didn't match the owner entry, try the user by name */
	rc = get_capas_for_principal(acl, DAOS_ACL_USER, authsys->user, capas);
	if (rc != -DER_NONEXIST)
		return rc;

	return get_capas_for_groups(acl, ownership, authsys, capas);
}

static int
get_auth_sys_payload(Auth__Token *token, Auth__Sys **payload)
{
	if (token->flavor != AUTH__FLAVOR__AUTH_SYS) {
		D_ERROR("Credential auth flavor not supported\n");
		return -DER_PROTO;
	}

	*payload = auth__sys__unpack(NULL, token->data.len, token->data.data);
	if (*payload == NULL) {
		D_ERROR("Invalid auth_sys payload\n");
		return -DER_PROTO;
	}

	return 0;
}

static void
filter_capas_based_on_flags(uint64_t flags, uint64_t *capas)
{
	if (flags & DAOS_PC_RO)
		*capas &= POOL_CAPAS_RO_MASK;
	else if (!(*capas & POOL_CAPAS_RO_MASK) ||
	         !(*capas & ~POOL_CAPAS_RO_MASK))
		/*
		 * User requested RW - if they don't have permissions for both
		 * read and write capas, we shouldn't grant them any.
		 */
		*capas = 0;
}

int
ds_sec_pool_get_capabilities(uint64_t flags, d_iov_t *cred,
			     struct ownership *ownership,
			     struct daos_acl *acl, uint64_t *capas)
{
	int		rc;
	Auth__Token	*token;
	Auth__Sys	*authsys;

	if (cred == NULL || ownership == NULL || acl == NULL || capas == NULL) {
		D_ERROR("NULL input\n");
		return -DER_INVAL;
	}

	if (ownership->user == NULL || ownership->group == NULL) {
		D_ERROR("Invalid ownership\n");
		return -DER_INVAL;
	}

	/* Pool flags are mutually exclusive */
	if ((flags != DAOS_PC_RO) && (flags != DAOS_PC_RW) &&
	    (flags != DAOS_PC_EX)) {
		D_ERROR("Invalid flags\n");
		return -DER_INVAL;
	}

	if (daos_acl_validate(acl) != 0) {
		D_ERROR("Invalid ACL\n");
		return -DER_INVAL;
	}

	rc = ds_sec_validate_credentials(cred, &token);
	if (rc != 0) {
		D_ERROR("Failed to validate credentials, rc="DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	rc = get_auth_sys_payload(token, &authsys);
	auth__token__free_unpacked(token, NULL);
	if (rc != 0)
		return rc;

	rc = get_authsys_capas(acl, ownership, authsys, capas);

	/*
	 * No match found to any specific entry. If there is an Everyone entry,
	 * we can use the capas for that.
	 */
	if (rc == -DER_NONEXIST)
		rc = get_capas_for_principal(acl, DAOS_ACL_EVERYONE, NULL,
					     capas);

	if (rc == 0) {
		filter_capas_based_on_flags(flags, capas);
	} else if (rc == -DER_NONEXIST) {
		*capas = 0; /* No permissions */
		rc = 0;
	}

	auth__sys__free_unpacked(authsys, NULL);
	return rc;
}

int
ds_sec_check_pool_access(struct daos_acl *acl, struct ownership *ownership,
			 d_iov_t *cred, uint64_t capas)
{
	int		rc = 0;
	uint64_t	actual_capas = 0;

	rc = ds_sec_pool_get_capabilities(capas, cred, ownership, acl,
					  &actual_capas);
	if (rc != 0)
		return rc;

	if (actual_capas == 0) {
		D_INFO("Access denied\n");
		return -DER_NO_PERM;
	}

	D_INFO("Access allowed\n");
	return 0;
}
