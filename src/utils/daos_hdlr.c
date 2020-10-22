/**
 * (C) Copyright 2016-2020 Intel Corporation.
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
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

/* daos_hdlr.c - resource and operation-specific handler functions
 * invoked by daos(8) utility
 */

#define D_LOGFAC	DD_FAC(client)
#define ENUM_KEY_BUF		32 /* size of each dkey/akey */
#define ENUM_LARGE_KEY_BUF	(512 * 1024) /* 512k large key */
#define ENUM_DESC_NR		5 /* number of keys/records returned by enum */
#define ENUM_DESC_BUF		512 /* all keys/records returned by enum */

#include <stdio.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <daos.h>
#include <daos/common.h>
#include <daos/rpc.h>
#include <daos/debug.h>
#include <daos/object.h>
#include <hdf5.h>

#include "daos_types.h"
#include "daos_api.h"
#include "daos_fs.h"
#include "daos_uns.h"
#include "daos_prop.h"

#include "daos_hdlr.h"

static int
parse_acl_file(const char *path, struct daos_acl **acl);

/* TODO: implement these pool op functions
 * int pool_stat_hdlr(struct cmd_args_s *ap);
 */

int
pool_get_prop_hdlr(struct cmd_args_s *ap)
{
	daos_prop_t			*prop_query;
	struct daos_prop_entry		*entry;
	int				rc = 0;
	int				rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_GET_PROP);

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RO, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	prop_query = daos_prop_alloc(0);
	if (prop_query == NULL)
		D_GOTO(out_disconnect, rc = -DER_NOMEM);

	rc = daos_pool_query(ap->pool, NULL, NULL, prop_query, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool query failed for properties: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	D_PRINT("Pool properties :\n");

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_LABEL);
	if (entry == NULL || entry->dpe_str == NULL) {
		fprintf(stderr, "label property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("label -> %s\n", entry->dpe_str);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_SPACE_RB);
	if (entry == NULL) {
		fprintf(stderr, "rebuild space ratio property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("rebuild space ratio -> "DF_U64"\n", entry->dpe_val);

	/* not set properties should get default value */
	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_SELF_HEAL);
	if (entry == NULL) {
		fprintf(stderr, "self-heal property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("self-heal -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_RECLAIM);
	if (entry == NULL) {
		fprintf(stderr, "reclaim property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("reclaim -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_ACL);
	if (entry == NULL || entry->dpe_val_ptr == NULL) {
		fprintf(stderr, "acl property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("acl ->\n");
	daos_acl_dump(entry->dpe_val_ptr);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_OWNER);
	if (entry == NULL || entry->dpe_str == NULL) {
		fprintf(stderr, "owner property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("owner -> %s\n", entry->dpe_str);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_PO_OWNER_GROUP);
	if (entry == NULL || entry->dpe_str == NULL) {
		fprintf(stderr, "owner-group property not found\n");
		D_GOTO(out_disconnect, rc = -DER_INVAL);
	}
	D_PRINT("owner-group -> %s\n", entry->dpe_str);

out_disconnect:
	daos_prop_free(prop_query);

	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;
}

int
pool_set_attr_hdlr(struct cmd_args_s *ap)
{
	size_t				value_size;
	int				rc = 0;
	int				rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_SET_ATTR);

	if (ap->attrname_str == NULL || ap->value_str == NULL) {
		fprintf(stderr, "both attribute name and value must be provided\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RW, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	value_size = strlen(ap->value_str);
	rc = daos_pool_set_attr(ap->pool, 1,
				(const char * const*)&ap->attrname_str,
				(const void * const*)&ap->value_str,
				(const size_t *)&value_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool set attr failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

out_disconnect:
	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;

}

int
pool_get_attr_hdlr(struct cmd_args_s *ap)
{
	size_t	attr_size, expected_size;
	char	*buf = NULL;
	int	rc = 0;
	int	rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_GET_ATTR);

	if (ap->attrname_str == NULL) {
		fprintf(stderr, "attribute name must be provided\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RO, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	/* evaluate required size to get attr */
	attr_size = 0;
	rc = daos_pool_get_attr(ap->pool, 1,
				(const char * const*)&ap->attrname_str, NULL,
				&attr_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool get attr failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	D_PRINT("Pool's %s attribute value: ", ap->attrname_str);
	if (attr_size <= 0) {
		D_PRINT("empty attribute\n");
		D_GOTO(out_disconnect, rc);
	}

	D_ALLOC(buf, attr_size);
	if (buf == NULL)
		D_GOTO(out_disconnect, rc = -DER_NOMEM);

	expected_size = attr_size;
	rc = daos_pool_get_attr(ap->pool, 1,
				(const char * const*)&ap->attrname_str,
				(void * const*)&buf, &attr_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool get attr failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	if (expected_size < attr_size)
		fprintf(stderr, "size required to get attributes has raised, value has been truncated\n");
	D_PRINT("%s\n", buf);

out_disconnect:
	if (buf != NULL)
		D_FREE(buf);

	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;

}

int
pool_list_attrs_hdlr(struct cmd_args_s *ap)
{
	size_t				 total_size, expected_size, cur = 0,
					 len;
	char				*buf = NULL;
	int				rc = 0;
	int				rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_LIST_ATTRS);

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RO, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	/* evaluate required size to get all attrs */
	total_size = 0;
	rc = daos_pool_list_attr(ap->pool, NULL, &total_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool list attr failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	D_PRINT("Pool attributes:\n");
	if (total_size == 0) {
		D_PRINT("No attributes\n");
		D_GOTO(out_disconnect, rc);
	}

	D_ALLOC(buf, total_size);
	if (buf == NULL)
		D_GOTO(out_disconnect, rc = -DER_NOMEM);

	expected_size = total_size;
	rc = daos_pool_list_attr(ap->pool, buf, &total_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool list attr failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	if (expected_size < total_size)
		fprintf(stderr, "size required to gather all attributes has raised, list has been truncated\n");
	while (cur < total_size) {
		len = strnlen(buf + cur, total_size - cur);
		if (len == total_size - cur) {
			fprintf(stderr,
				"end of buf reached but no end of string encountered, ignoring\n");
			break;
		}
		D_PRINT("%s\n", buf + cur);
		cur += len + 1;
	}

out_disconnect:
	if (buf != NULL)
		D_FREE(buf);

	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;

}

int
pool_list_containers_hdlr(struct cmd_args_s *ap)
{
	daos_size_t			 ncont = 0;
	const daos_size_t		 extra_cont_margin = 16;
	struct daos_pool_cont_info	*conts = NULL;
	int				 i;
	int				 rc = 0;
	int				 rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_LIST_CONTAINERS);

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RO, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	/* Issue first API call to get current number of containers */
	rc = daos_pool_list_cont(ap->pool, &ncont, NULL /* cbuf */,
				 NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "pool get ncont failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	/* If no containers, no need for a second call */
	if (ncont == 0)
		D_GOTO(out_disconnect, rc);

	/* Allocate conts[] with some margin to avoid -DER_TRUNC if more
	 * containers were created after the first call
	 */
	ncont += extra_cont_margin;
	D_ALLOC_ARRAY(conts, ncont);
	if (conts == NULL)
		D_GOTO(out_disconnect, rc = -DER_NOMEM);

	rc = daos_pool_list_cont(ap->pool, &ncont, conts, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "pool list containers failed: %d\n", rc);
		D_GOTO(out_free, rc);
	}

	for (i = 0; i < ncont; i++) {
		D_PRINT(DF_UUIDF"\n", DP_UUID(conts[i].pci_uuid));
	}

out_free:
	D_FREE(conts);

out_disconnect:
	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;
}

int
pool_query_hdlr(struct cmd_args_s *ap)
{
	daos_pool_info_t		 pinfo = {0};
	struct daos_pool_space		*ps = &pinfo.pi_space;
	struct daos_rebuild_status	*rstat = &pinfo.pi_rebuild_st;
	int				 i;
	int				rc = 0;
	int				rc2;

	assert(ap != NULL);
	assert(ap->p_op == POOL_QUERY);

	rc = daos_pool_connect(ap->p_uuid, ap->sysname,
			       ap->mdsrv, DAOS_PC_RO, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	pinfo.pi_bits = DPI_ALL;
	rc = daos_pool_query(ap->pool, NULL, &pinfo, NULL, NULL);
	if (rc != 0) {
		fprintf(stderr, "pool query failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}
	D_PRINT("Pool "DF_UUIDF", ntarget=%u, disabled=%u, version=%u\n",
		DP_UUID(pinfo.pi_uuid), pinfo.pi_ntargets,
		pinfo.pi_ndisabled, pinfo.pi_map_ver);

	D_PRINT("Pool space info:\n");
	D_PRINT("- Target(VOS) count:%d\n", ps->ps_ntargets);
	for (i = DAOS_MEDIA_SCM; i < DAOS_MEDIA_MAX; i++) {
		D_PRINT("- %s:\n",
			i == DAOS_MEDIA_SCM ? "SCM" : "NVMe");
		D_PRINT("  Total size: "DF_U64"\n",
			ps->ps_space.s_total[i]);
		D_PRINT("  Free: "DF_U64", min:"DF_U64", max:"DF_U64", "
			"mean:"DF_U64"\n", ps->ps_space.s_free[i],
			ps->ps_free_min[i], ps->ps_free_max[i],
			ps->ps_free_mean[i]);
	}

	if (rstat->rs_errno == 0) {
		char	*sstr;

		if (rstat->rs_version == 0)
			sstr = "idle";
		else if (rstat->rs_done)
			sstr = "done";
		else
			sstr = "busy";

		D_PRINT("Rebuild %s, "DF_U64" objs, "DF_U64" recs\n",
			sstr, rstat->rs_obj_nr, rstat->rs_rec_nr);
	} else {
		D_PRINT("Rebuild failed, rc=%d, status=%d\n",
			rc, rstat->rs_errno);
	}

out_disconnect:
	/* Pool disconnect  in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);

	if (rc == 0)
		rc = rc2;
out:
	return rc;
}

/* TODO implement the following container op functions
 * all with signatures similar to this:
 * int cont_FN_hdlr(struct cmd_args_s *ap)
 *
 * cont_list_objs_hdlr()
 * int cont_stat_hdlr()
 * int cont_del_attr_hdlr()
 * int cont_rollback_hdlr()
 */

int
cont_list_snaps_hdlr(struct cmd_args_s *ap)
{
	daos_epoch_t *buf = NULL;
	daos_anchor_t anchor;
	int rc, i, snaps_count, expected_count;

	/* evaluate size for listing */
	snaps_count = 0;
	memset(&anchor, 0, sizeof(anchor));
	rc = daos_cont_list_snap(ap->cont, &snaps_count, NULL, NULL, &anchor,
				 NULL);
	if (rc != 0) {
		fprintf(stderr, "cont list snaps failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	D_PRINT("Container's snapshots :\n");
	if (!daos_anchor_is_eof(&anchor)) {
		fprintf(stderr, "too many snapshots returned\n");
		D_GOTO(out, rc = -DER_INVAL);
	}
	if (snaps_count == 0) {
		D_PRINT("no snapshots\n");
		D_GOTO(out, rc);
	}

	D_ALLOC_ARRAY(buf, snaps_count);
	if (buf == NULL)
		D_GOTO(out, rc = -DER_NOMEM);

	expected_count = snaps_count;
	memset(&anchor, 0, sizeof(anchor));
	rc = daos_cont_list_snap(ap->cont, &snaps_count, buf, NULL, &anchor,
				 NULL);
	if (rc != 0) {
		fprintf(stderr, "cont list snaps failed: %d\n", rc);
		D_GOTO(out, rc);
	}
	if (expected_count < snaps_count)
		fprintf(stderr, "size required to gather all snapshots has raised, list has been truncated\n");

	for (i = 0; i < min(expected_count, snaps_count); i++)
		D_PRINT(DF_U64" ", buf[i]);
	D_PRINT("\n");

out:
	if (buf != NULL)
		D_FREE(buf);

	return rc;
}

int
cont_create_snap_hdlr(struct cmd_args_s *ap)
{
	int rc;

	rc = daos_cont_create_snap(ap->cont, &ap->epc, ap->snapname_str, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont create snap failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	D_PRINT("snapshot/epoch "DF_U64" has been created\n", ap->epc);
out:
	return rc;
}

int
cont_destroy_snap_hdlr(struct cmd_args_s *ap)
{
	daos_epoch_range_t epr;
	int rc;

	if (ap->epc == 0 &&
	    (ap->epcrange_begin == 0 || ap->epcrange_end == 0)) {
		fprintf(stderr, "a single epoch or a range must be provided\n");
		D_GOTO(out, rc = -DER_INVAL);
	}
	if (ap->epc != 0 &&
	    (ap->epcrange_begin != 0 || ap->epcrange_end != 0)) {
		fprintf(stderr, "both a single epoch and a range not allowed\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	if (ap->epc != 0) {
		epr.epr_lo = ap->epc;
		epr.epr_hi = ap->epc;
	} else {
		epr.epr_lo = ap->epcrange_begin;
		epr.epr_hi = ap->epcrange_end;
	}

	rc = daos_cont_destroy_snap(ap->cont, epr, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont destroy snap failed: %d\n", rc);
		D_GOTO(out, rc);
	}

out:
	return rc;
}

int
cont_set_attr_hdlr(struct cmd_args_s *ap)
{
	size_t				value_size;
	int				rc = 0;

	if (ap->attrname_str == NULL || ap->value_str == NULL) {
		fprintf(stderr, "both attribute name and value must be provided\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	value_size = strlen(ap->value_str);
	rc = daos_cont_set_attr(ap->cont, 1,
				(const char * const*)&ap->attrname_str,
				(const void * const*)&ap->value_str,
				(const size_t *)&value_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont set attr failed: %d\n", rc);
		D_GOTO(out, rc);
	}

out:
	return rc;

}

int
cont_get_attr_hdlr(struct cmd_args_s *ap)
{
	size_t	attr_size, expected_size;
	char	*buf= NULL;
	int	rc = 0;

	if (ap->attrname_str == NULL) {
		fprintf(stderr, "attribute name must be provided\n");
		D_GOTO(out, rc = -DER_INVAL);
	}

	/* evaluate required size to get attr */
	attr_size = 0;
	rc = daos_cont_get_attr(ap->cont, 1,
				(const char * const*)&ap->attrname_str, NULL,
				&attr_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont get attr failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	D_PRINT("Container's %s attribute value: ", ap->attrname_str);
	if (attr_size <= 0) {
		D_PRINT("empty attribute\n");
		D_GOTO(out, rc);
	}

	D_ALLOC(buf, attr_size);
	if (buf == NULL)
		D_GOTO(out, rc = -DER_NOMEM);

	expected_size = attr_size;
	rc = daos_cont_get_attr(ap->cont, 1,
				(const char * const*)&ap->attrname_str,
				(void * const*)&buf, &attr_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont get attr failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	if (expected_size < attr_size)
		fprintf(stderr, "size required to get attributes has raised, value has been truncated\n");
	D_PRINT("%s\n", buf);

out:
	if (buf != NULL)
		D_FREE(buf);

	return rc;

}

int
cont_list_attrs_hdlr(struct cmd_args_s *ap)
{
	size_t				 size, total_size, expected_size,
					 cur = 0, len;
	char				*buf = NULL;
	int				rc = 0;

	/* evaluate required size to get all attrs */
	total_size = 0;
	rc = daos_cont_list_attr(ap->cont, NULL, &total_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont list attr failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	D_PRINT("Container attributes:\n");
	if (total_size == 0) {
		D_PRINT("No attributes\n");
		D_GOTO(out, rc);
	}

	D_ALLOC(buf, total_size);
	if (buf == NULL)
		D_GOTO(out, rc = -DER_NOMEM);

	expected_size = total_size;
	rc = daos_cont_list_attr(ap->cont, buf, &total_size, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont list attr failed: %d\n", rc);
		D_GOTO(out, rc);
	}

	if (expected_size < total_size)
		fprintf(stderr, "size required to gather all attributes has raised, list has been truncated\n");
	size = min(expected_size, total_size);
	while (cur < size) {
		len = strnlen(buf + cur, size - cur);
		if (len == size - cur) {
			fprintf(stderr,
				"end of buf reached but no end of string encountered, ignoring\n");
			break;
		}
		D_PRINT("%s\n", buf + cur);
		cur += len + 1;
	}

out:
	if (buf != NULL)
		D_FREE(buf);

	return rc;

}

/* cont_get_prop_hdlr() - get container properties */
int
cont_get_prop_hdlr(struct cmd_args_s *ap)
{
	daos_prop_t		*prop_query;
	struct daos_prop_entry	*entry;
	char			type[10] = {};
	int			rc = 0;
	uint32_t		i;
	uint32_t		entry_type;

	/*
	 * Get all props except the ACL
	 */
	prop_query = daos_prop_alloc(DAOS_PROP_CO_NUM - 1);
	if (prop_query == NULL)
		return -DER_NOMEM;

	entry_type = DAOS_PROP_CO_MIN + 1;
	for (i = 0; i < prop_query->dpp_nr; entry_type++) {
		if (entry_type == DAOS_PROP_CO_ACL)
			continue; /* skip ACL */
		prop_query->dpp_entries[i].dpe_type = entry_type;
		i++;
	}

	rc = daos_cont_query(ap->cont, NULL, prop_query, NULL);
	if (rc) {
		fprintf(stderr, "Container query failed, result: %d\n", rc);
		D_GOTO(err_out, rc);
	}

	D_PRINT("Container properties :\n");

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_LABEL);
	if (entry == NULL || entry->dpe_str == NULL) {
		fprintf(stderr, "label property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("label -> %s\n", entry->dpe_str);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_LAYOUT_TYPE);
	if (entry == NULL) {
		fprintf(stderr, "layout type property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	daos_unparse_ctype(entry->dpe_val, type);
	D_PRINT("layout type -> "DF_U64"/%s\n", entry->dpe_val, type);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_LAYOUT_VER);
	if (entry == NULL) {
		fprintf(stderr, "layout version property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("layout version -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_CSUM);
	if (entry == NULL) {
		fprintf(stderr, "checksum type property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("checksum type -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_CSUM_CHUNK_SIZE);
	if (entry == NULL) {
		fprintf(stderr, "checksum chunk-size property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("checksum chunk-size -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_CSUM_SERVER_VERIFY);
	if (entry == NULL) {
		fprintf(stderr, "checksum verification on server property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("checksum verification on server -> "DF_U64"\n",
		entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_REDUN_FAC);
	if (entry == NULL) {
		fprintf(stderr, "redundancy factor property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("redundancy factor -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_REDUN_LVL);
	if (entry == NULL) {
		fprintf(stderr, "redundancy level property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("redundancy level -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_SNAPSHOT_MAX);
	if (entry == NULL) {
		fprintf(stderr, "max snapshots property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("max snapshots -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_COMPRESS);
	if (entry == NULL) {
		fprintf(stderr, "compression type property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("compression type -> "DF_U64"\n", entry->dpe_val);

	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_ENCRYPT);
	if (entry == NULL) {
		fprintf(stderr, "encryption type property not found\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}
	D_PRINT("encryption type -> "DF_U64"\n", entry->dpe_val);

err_out:
	daos_prop_free(prop_query);
	return rc;
}

int
cont_set_prop_hdlr(struct cmd_args_s *ap)
{
	int			 rc;
	struct daos_prop_entry	*entry;
	uint32_t		 i;

	if (ap->props == NULL || ap->props->dpp_nr == 0) {
		fprintf(stderr, "at least one property must be requested\n");
		D_GOTO(err_out, rc = -DER_INVAL);
	}

	/* Validate the properties are supported for set */
	for (i = 0; i < ap->props->dpp_nr; i++) {
		entry = &(ap->props->dpp_entries[i]);
		if (entry->dpe_type != DAOS_PROP_CO_LABEL) {
			fprintf(stderr, "property not supported for set\n");
			D_GOTO(err_out, rc = -DER_INVAL);
		}
	}

	rc = daos_cont_set_prop(ap->cont, ap->props, NULL);
	if (rc) {
		fprintf(stderr, "Container set-prop failed, result: %d\n", rc);
		D_GOTO(err_out, rc);
	}

	D_PRINT("Properties were successfully set\n");

err_out:
	return rc;
}

static size_t
get_num_prop_entries_to_add(struct cmd_args_s *ap)
{
	size_t nr = 0;

	if (ap->aclfile)
		nr++;
	if (ap->user)
		nr++;
	if (ap->group)
		nr++;

	return nr;
}

/*
 * Returns the first empty prop entry in ap->props.
 * If ap->props wasn't set previously, a new prop is created.
 */
static int
get_first_empty_prop_entry(struct cmd_args_s *ap,
			   struct daos_prop_entry **entry)
{
	size_t nr = 0;

	nr = get_num_prop_entries_to_add(ap);
	if (nr == 0) {
		*entry = NULL;
		return 0; /* nothing to do */
	}

	if (ap->props == NULL) {
		/*
		 * Note that we don't control the memory this way, the prop is
		 * freed by the external caller
		 */
		ap->props = daos_prop_alloc(nr);
		if (ap->props == NULL) {
			fprintf(stderr,
				"failed to allocate memory while processing "
				"access control parameters\n");
			return -DER_NOMEM;
		}
		*entry = &(ap->props->dpp_entries[0]);
	} else {
		*entry = &(ap->props->dpp_entries[ap->props->dpp_nr]);
		ap->props->dpp_nr += nr;
	}

	if (ap->props->dpp_nr > DAOS_PROP_ENTRIES_MAX_NR) {
		fprintf(stderr,
			"too many properties supplied. Try again with "
			"fewer props set.\n");
		return -DER_INVAL;
	}

	return 0;
}

static int
update_props_for_access_control(struct cmd_args_s *ap)
{
	int			rc = 0;
	struct daos_acl		*acl = NULL;
	struct daos_prop_entry	*entry = NULL;

	rc = get_first_empty_prop_entry(ap, &entry);
	if (rc != 0 || entry == NULL)
		return rc;

	D_ASSERT(entry->dpe_type == 0);
	D_ASSERT(entry->dpe_val_ptr == NULL);

	/*
	 * When we allocate new memory here, we always do it in the prop entry,
	 * which is a pointer into ap->props.
	 * This will be freed by the external caller on exit, so we don't have
	 * to worry about it here.
	 */

	if (ap->aclfile) {
		rc = parse_acl_file(ap->aclfile, &acl);
		if (rc != 0)
			return rc;

		entry->dpe_type = DAOS_PROP_CO_ACL;
		entry->dpe_val_ptr = acl;
		acl = NULL; /* acl will be freed with the prop now */

		entry++;
	}

	if (ap->user) {
		if (!daos_acl_principal_is_valid(ap->user)) {
			fprintf(stderr,
				"invalid user name.\n");
			return -DER_INVAL;
		}

		entry->dpe_type = DAOS_PROP_CO_OWNER;
		D_STRNDUP(entry->dpe_str, ap->user, DAOS_ACL_MAX_PRINCIPAL_LEN);
		if (entry->dpe_str == NULL) {
			fprintf(stderr,
				"failed to allocate memory for user name.\n");
			return -DER_NOMEM;
		}

		entry++;
	}

	if (ap->group) {
		if (!daos_acl_principal_is_valid(ap->group)) {
			fprintf(stderr,
				"invalid group name.\n");
			return -DER_INVAL;
		}

		entry->dpe_type = DAOS_PROP_CO_OWNER_GROUP;
		D_STRNDUP(entry->dpe_str, ap->group,
			  DAOS_ACL_MAX_PRINCIPAL_LEN);
		if (entry->dpe_str == NULL) {
			fprintf(stderr,
				"failed to allocate memory for group name.\n");
			return -DER_NOMEM;
		}

		entry++;
	}

	return 0;
}

/* cont_create_hdlr() - create container by UUID */
int
cont_create_hdlr(struct cmd_args_s *ap)
{
	int rc;

	rc = update_props_for_access_control(ap);
	if (rc != 0)
		return rc;

	/** allow creating a POSIX container without a link in the UNS path */
	if (ap->type == DAOS_PROP_CO_LAYOUT_POSIX) {
		dfs_attr_t attr;

		attr.da_id = 0;
		attr.da_oclass_id = ap->oclass;
		attr.da_chunk_size = ap->chunk_size;
		attr.da_props = ap->props;
		rc = dfs_cont_create(ap->pool, ap->c_uuid, &attr, NULL, NULL);
	} else {
		rc = daos_cont_create(ap->pool, ap->c_uuid, ap->props, NULL);
	}

	if (rc != 0) {
		fprintf(stderr, "failed to create container: %d\n", rc);
		return rc;
	}

	fprintf(stdout, "Successfully created container "DF_UUIDF"\n",
		DP_UUID(ap->c_uuid));

	return rc;
}

/* cont_create_uns_hdlr() - create container and link to
 * POSIX filesystem directory or HDF5 file.
 */
int
cont_create_uns_hdlr(struct cmd_args_s *ap)
{
	struct duns_attr_t	dattr = {0};
	char			type[10];
	int			rc;
	const int		RC_PRINT_HELP = 2;

	/* Required: pool UUID, container type, obj class, chunk_size.
	 * Optional: user-specified container UUID.
	 */
	ARGS_VERIFY_PATH_CREATE(ap, err_rc, rc = RC_PRINT_HELP);

	uuid_copy(dattr.da_puuid, ap->p_uuid);
	uuid_copy(dattr.da_cuuid, ap->c_uuid);
	dattr.da_type = ap->type;
	dattr.da_oclass_id = ap->oclass;
	dattr.da_chunk_size = ap->chunk_size;
	dattr.da_props = ap->props;

	rc = duns_create_path(ap->pool, ap->path, &dattr);
	if (rc) {
		fprintf(stderr, "duns_create_path() error: %s\n", strerror(rc));
		D_GOTO(err_rc, rc);
	}

	uuid_copy(ap->c_uuid, dattr.da_cuuid);
	daos_unparse_ctype(ap->type, type);
	fprintf(stdout, "Successfully created container "DF_UUIDF" type %s\n",
			DP_UUID(ap->c_uuid), type);

	return 0;

err_rc:
	return rc;
}

int
cont_query_hdlr(struct cmd_args_s *ap)
{
	daos_cont_info_t	cont_info;
	char			oclass[10], type[10];
	int			rc;

	rc = daos_cont_query(ap->cont, &cont_info, NULL, NULL);
	if (rc) {
		fprintf(stderr, "Container query failed, result: %d\n", rc);
		D_GOTO(err_out, rc);
	}

	printf("Pool UUID:\t"DF_UUIDF"\n", DP_UUID(ap->p_uuid));
	printf("Container UUID:\t"DF_UUIDF"\n", DP_UUID(cont_info.ci_uuid));
	printf("Number of snapshots: %i\n", (int)cont_info.ci_nsnapshots);
	printf("Latest Persistent Snapshot: %i\n",
		(int)cont_info.ci_lsnapshot);
	printf("Highest Aggregated Epoch: "DF_U64"\n", cont_info.ci_hae);
	/* TODO: list snapshot epoch numbers, including ~80 column wrap. */

	if (ap->path != NULL) {
		/* cont_op_hdlr() already did resolve_by_path()
		 * all resulting fields should be populated
		 */
		assert(ap->type != DAOS_PROP_CO_LAYOUT_UNKOWN);

		printf("DAOS Unified Namespace Attributes on path %s:\n",
			ap->path);
		daos_unparse_ctype(ap->type, type);
		printf("Container Type:\t%s\n", type);

		if (ap->type == DAOS_PROP_CO_LAYOUT_POSIX) {
			dfs_t		*dfs;
			dfs_attr_t	attr;

			rc = dfs_mount(ap->pool, ap->cont, O_RDONLY, &dfs);
			if (rc) {
				fprintf(stderr, "dfs_mount failed (%d)\n", rc);
				D_GOTO(err_out, rc);
			}

			dfs_query(dfs, &attr);
			daos_oclass_id2name(attr.da_oclass_id, oclass);
			printf("Object Class:\t%s\n", oclass);
			printf("Chunk Size:\t%zu\n", attr.da_chunk_size);

			rc = dfs_umount(dfs);
			if (rc) {
				fprintf(stderr, "dfs_umount failed (%d)\n", rc);
				D_GOTO(err_out, rc);
			}
		}
	}

	return 0;

err_out:
	return rc;
}

int
cont_destroy_hdlr(struct cmd_args_s *ap)
{
	int	rc;

	if (ap->path) {
		rc = duns_destroy_path(ap->pool, ap->path);
		if (rc)
			fprintf(stderr, "duns_destroy_path() failed %s (%s)\n",
				ap->path, strerror(rc));
		else
			fprintf(stdout, "Successfully destroyed path %s\n",
				ap->path);
		return rc;
	}

	/* TODO: when API supports, change arg 3 to ap->force_destroy. */
	rc = daos_cont_destroy(ap->pool, ap->c_uuid, 1, NULL);
	if (rc != 0)
		fprintf(stderr, "failed to destroy container: %d\n", rc);
	else
		fprintf(stdout, "Successfully destroyed container "
				DF_UUIDF"\n", DP_UUID(ap->c_uuid));

	return rc;
}

static int
copy_recx_single(daos_key_t *dkey,
		 daos_handle_t *src_oh,
		 daos_handle_t *dst_oh,
		 daos_iod_t *iod)
{
	/* if iod_type is single value just fetch iod size from source
	 * and update in destination object */
	int         buf_len = (int)(*iod).iod_size;
	char        buf[buf_len];
	d_sg_list_t sgl;
	d_iov_t     iov;
	int	    rc;

	/* set sgl values */
	sgl.sg_nr     = 1;
	sgl.sg_nr_out = 0;
	sgl.sg_iovs   = &iov;
	d_iov_set(&iov, buf, buf_len);
        rc = daos_obj_fetch(*src_oh, DAOS_TX_NONE, 0, dkey, 1, iod, &sgl, NULL, NULL);
	printf("\tRC SINGLE VAL FETCH: %d, IOD SIZE: %d\n", rc, (int)(*iod).iod_size);
        rc = daos_obj_update(*dst_oh, DAOS_TX_NONE, 0, dkey, 1, iod, &sgl, NULL);
	printf("\tRC SINGLE VAL UPDATE: %d, IOD SIZE: %d\n", rc, (int)(*iod).iod_size);
	return rc;
}

static int
copy_recx_array(daos_key_t *dkey,
		daos_key_t *akey,
		daos_handle_t *src_oh,
		daos_handle_t *dst_oh,
		daos_iod_t *iod)
{
	daos_anchor_t recx_anchor = {0}; 
	int rc;
	int i;
	while (!daos_anchor_is_eof(&recx_anchor)) {
		daos_epoch_range_t	eprs[5];
		daos_recx_t		recxs[5];
		daos_size_t		size;

		/* list all recx for this dkey/akey */
		uint32_t number = 5;
		rc = daos_obj_list_recx(*src_oh, DAOS_TX_NONE, dkey,
			akey, &size, &number, recxs, eprs, &recx_anchor,
			true, NULL);

		/* if no recx is returned for this dkey/akey move on */
		if (number == 0) 
			continue;
		for (i = 0; i < number; i++) {
			uint64_t    buf_len = recxs[i].rx_nr;
		        char        buf[buf_len];
			d_sg_list_t sgl;
			d_iov_t     iov;

			/* set iod values */
			(*iod).iod_type  = DAOS_IOD_ARRAY;
			(*iod).iod_size  = 1;
			(*iod).iod_nr    = 1;
			(*iod).iod_recxs = &recxs[i];

			/* set sgl values */
			sgl.sg_nr     = 1;
			sgl.sg_nr_out = 0;
			sgl.sg_iovs   = &iov;

			d_iov_set(&iov, buf, buf_len);	
			//printf("\ti: %d iod_size: %d rx_nr:%d, rx_idx:%d\n",
			//	i, (int)size, (int)recxs[i].rx_nr, (int)recxs[i].rx_idx);
			/* fetch recx values from source */
                        rc = daos_obj_fetch(*src_oh, DAOS_TX_NONE, 0, dkey, 1, iod,
				&sgl, NULL, NULL);
			//printf("\tRC ARRAY VAL FETCH: %d, SGL DATA LEN: %d\n", rc,
				//(int)sgl.sg_iovs[0].iov_len);
			/* update fetched recx values and place in destination object */
                        rc = daos_obj_update(*dst_oh, DAOS_TX_NONE, 0, dkey, 1, iod,
				&sgl, NULL);
			//printf("\tRC ARRAY VAL UPDATE: %d, SGL DATA LEN: %d\n", rc,
			//	(int)sgl.sg_iovs[0].iov_len);
			}
		}
	return rc;
}

static int
copy_list_keys(daos_handle_t *src_oh,
	       daos_handle_t *dst_oh)
{
	/* loop to enumerate dkeys */
	daos_anchor_t dkey_anchor = {0}; 
	int rc;
	while (!daos_anchor_is_eof(&dkey_anchor)) {
		d_sg_list_t     sgl;
		d_iov_t         iov;
		daos_key_desc_t dkey_kds[ENUM_DESC_NR]       = {0};
		uint32_t        dkey_number                  = ENUM_DESC_NR;
		char            dkey_enum_buf[ENUM_DESC_BUF] = {0};
                char 		dkey[ENUM_KEY_BUF]           = {0};

                sgl.sg_nr     = 1;
	        sgl.sg_nr_out = 0;
	        sgl.sg_iovs   = &iov;

	        d_iov_set(&iov, dkey_enum_buf, ENUM_DESC_BUF);

		/* get dkeys */
		rc = daos_obj_list_dkey(*src_oh, DAOS_TX_NONE, &dkey_number, dkey_kds,
			&sgl, &dkey_anchor, NULL);
		if (rc)
			return daos_der2errno(rc);       

		/* if no dkeys were returned move on */
		if (dkey_number == 0)
			continue;

		char* ptr;
		int   rc;
		int   j;
		/* parse out individual dkeys based on key length and numver of dkeys returned */
               	for (ptr = dkey_enum_buf, j = 0; j < dkey_number; j++) {
			/* Print enumerated dkeys */
            		daos_key_t diov;
			snprintf(dkey, dkey_kds[j].kd_key_len + 1, "%s", ptr);
			d_iov_set(&diov, (void*)dkey, dkey_kds[j].kd_key_len);
			printf("j:%d dkey iov buf:%s len:%d\n", j, (char*)diov.iov_buf, (int)dkey_kds[j].kd_key_len);
			ptr += dkey_kds[j].kd_key_len;

			/* loop to enumerate akeys */
			daos_anchor_t akey_anchor = {0}; 
			while (!daos_anchor_is_eof(&akey_anchor)) {
				d_sg_list_t     sgl;
				d_iov_t         iov;
				daos_key_desc_t akey_kds[ENUM_DESC_NR]       = {0};
				uint32_t        akey_number                  = ENUM_DESC_NR;
				char            akey_enum_buf[ENUM_DESC_BUF] = {0};
				char 		akey[ENUM_KEY_BUF] 	     = {0};

				sgl.sg_nr     = 1;
				sgl.sg_nr_out = 0;
				sgl.sg_iovs   = &iov;

				d_iov_set(&iov, akey_enum_buf, ENUM_DESC_BUF);

				/* get akeys */
				rc = daos_obj_list_akey(*src_oh, DAOS_TX_NONE, &diov, &akey_number, akey_kds,
							&sgl, &akey_anchor, NULL);
				if (rc)
					return daos_der2errno(rc);       

				/* if no akeys returned move on */
				if (akey_number == 0)
					continue;
				int j;
				char* ptr;
				/* parse out individual akeys based on key length and numver of dkeys returned */
				for (ptr = akey_enum_buf, j = 0; j < akey_number; j++) {
					daos_key_t aiov;
					daos_iod_t iod;
					snprintf(akey, akey_kds[j].kd_key_len + 1, "%s", ptr);
					d_iov_set(&aiov, (void*)akey, akey_kds[j].kd_key_len);
					printf("\tj:%d akey:%s len:%d\n", j, (char*)aiov.iov_buf, (int)akey_kds[j].kd_key_len);

					/* set iod values */
					iod.iod_nr   = 1;
					iod.iod_type = DAOS_IOD_SINGLE;
					iod.iod_size = DAOS_REC_ANY;

					d_iov_set(&iod.iod_name, (void*)akey, strlen(akey));
					/* I meant with the probe that you do a fetch (with NULL sgl)
					* of single value type, and if that returns iod_size == 0, then
					* a single value does not exist.*/
					/* do fetch with sgl == NULL to check if iod type (ARRAY OR SINGLE VAL) */
					rc = daos_obj_fetch(*src_oh, DAOS_TX_NONE, 0, &diov, 1, &iod, NULL, NULL, NULL);

					/* if iod_size == 0 then this is a DAOS_IOD_ARRAY type */
					if ((int)iod.iod_size == 0) {
						rc = copy_recx_array(&diov, &aiov, src_oh, dst_oh, &iod);
					} else {
						rc = copy_recx_single(&diov, src_oh, dst_oh, &iod);
					}
					/* advance to next akey returned */	
					ptr += akey_kds[j].kd_key_len;
				}
			}
		}
	}
	return rc;
}

static int
serialize_recx_single(hid_t *rx_dset,
		 hid_t *rx_dtype,
		 hid_t *rx_dspace,
		 daos_key_t *dkey,
		 daos_handle_t *oh,
		 daos_iod_t *iod)
{
	/* if iod_type is single value just fetch iod size from source
	 * and update in destination object */
	int         buf_len = (int)(*iod).iod_size;
	char        buf[buf_len];
	d_sg_list_t sgl;
	d_iov_t     iov;
	int	    rc;

	/* set sgl values */
	sgl.sg_nr     = 1;
	sgl.sg_nr_out = 0;
	sgl.sg_iovs   = &iov;
	d_iov_set(&iov, buf, buf_len);
        rc = daos_obj_fetch(*oh, DAOS_TX_NONE, 0, dkey, 1, iod, &sgl, NULL, NULL);
	printf("\tRC SINGLE VAL FETCH: %d, IOD SIZE: %d\n", rc, (int)(*iod).iod_size);
	hsize_t rx_dims[1] = {1};
	hid_t rx_memspace = H5Screate_simple(1, rx_dims, NULL);
	/* write single val record to dataset */
	H5Dset_extent(*rx_dset, rx_dims);
	*rx_dspace = H5Dget_space(*rx_dset);
	hsize_t start = 0;
	hsize_t count = 1; 
	H5Sselect_hyperslab(*rx_dspace, H5S_SELECT_AND, &start, NULL, &count, NULL);
	H5Dwrite(*rx_dset, *rx_dtype, rx_memspace, *rx_dspace, H5P_DEFAULT, sgl.sg_iovs[0].iov_buf);
	return rc;
}


static int
serialize_recx_array(hid_t *rx_dset,
		hid_t *rx_dspace,
		daos_key_t *dkey,
		daos_key_t *akey,
		daos_handle_t *oh,
		daos_iod_t *iod)
{
	daos_anchor_t recx_anchor = {0}; 
	int rc;
	int i;
	while (!daos_anchor_is_eof(&recx_anchor)) {
		daos_epoch_range_t	eprs[5];
		daos_recx_t		recxs[5];
		daos_size_t		size;

		/* list all recx for this dkey/akey */
	        uint32_t number = 1;
		rc = daos_obj_list_recx(*oh, DAOS_TX_NONE, dkey,
			akey, &size, &number, recxs, eprs, &recx_anchor,
			true, NULL);

		/* if no recx is returned for this dkey/akey move on */
		if (number == 0) 
			continue;
		for (i = 0; i < number; i++) {
			uint64_t    buf_len = recxs[i].rx_nr;
		        char        buf[buf_len];
			d_sg_list_t sgl;
			d_iov_t     iov;

			/* set iod values */
			(*iod).iod_type  = DAOS_IOD_ARRAY;
			(*iod).iod_size  = 1;
			(*iod).iod_nr    = 1;
			(*iod).iod_recxs = &recxs[i];

			/* set sgl values */
			sgl.sg_nr     = 1;
			sgl.sg_nr_out = 0;
			sgl.sg_iovs   = &iov;

			d_iov_set(&iov, buf, buf_len);	
			printf("\ti: %d iod_size: %d rx_nr:%d, rx_idx:%d\n",
				i, (int)size, (int)recxs[i].rx_nr, (int)recxs[i].rx_idx);
			/* fetch recx values from source */
                        rc = daos_obj_fetch(*oh, DAOS_TX_NONE, 0, dkey, 1, iod,
				&sgl, NULL, NULL);
			printf("\tRC ARRAY VAL FETCH: %d, SGL DATA LEN: %d\n", rc,
				(int)sgl.sg_iovs[0].iov_len);
			/* write data to record dset */
			hsize_t rx_dims[1] = {recxs[i].rx_nr};
			hid_t rx_memspace = H5Screate_simple(1, rx_dims, NULL);
			/* extend dataset */
			H5Dset_extent(*rx_dset, rx_dims);
			*rx_dspace = H5Dget_space(*rx_dset);
			hsize_t start = recxs[i].rx_idx;
			hsize_t count = recxs[i].rx_nr;
			H5Sselect_hyperslab(*rx_dspace, H5S_SELECT_AND, &start, NULL, &count, NULL);
			hid_t rx_dtype = H5Tcreate(H5T_OPAQUE, (*iod).iod_size);
			H5Tset_tag(rx_dtype, "Opaque dtype");
			H5Dwrite(*rx_dset, rx_dtype, rx_memspace, *rx_dspace, H5P_DEFAULT, sgl.sg_iovs[0].iov_buf);
		}
	}
	return rc;
}


static int
serialize_list_keys(hid_t *file,
		    dkey_t **dk,
		    uint64_t *dk_index,
		    akey_t **ak,
		    uint64_t *ak_index,
		    uint64_t *dkey_offset,
		    uint64_t *akey_offset,
		    uint64_t *total_dkeys,
		    uint64_t *total_akeys,
		    daos_handle_t *oh)
{
	/* loop to enumerate dkeys */
	daos_anchor_t dkey_anchor = {0}; 
	int rc;
	while (!daos_anchor_is_eof(&dkey_anchor)) {
		d_sg_list_t     sgl;
		d_iov_t         iov;
		daos_key_desc_t dkey_kds[ENUM_DESC_NR]       = {0};
		uint32_t        dkey_number                  = ENUM_DESC_NR;
		char            dkey_enum_buf[ENUM_DESC_BUF] = {0};
                char 		dkey[ENUM_KEY_BUF]           = {0};

                sgl.sg_nr     = 1;
	        sgl.sg_nr_out = 0;
	        sgl.sg_iovs   = &iov;

	        d_iov_set(&iov, dkey_enum_buf, ENUM_DESC_BUF);

		/* get dkeys */
		rc = daos_obj_list_dkey(*oh, DAOS_TX_NONE, &dkey_number, dkey_kds,
			&sgl, &dkey_anchor, NULL);
		if (rc)
			return daos_der2errno(rc);       

		/* if no dkeys were returned move on */
		if (dkey_number == 0)
			continue;
		*dk = realloc(*dk,  (dkey_number + *total_dkeys) * sizeof(dkey_t));
		char* ptr;
		char* dkey_data_ptr;
		int   rc;
		int   j;
		/* parse out individual dkeys based on key length and numver of dkeys returned */
               	for (ptr = dkey_enum_buf, j = 0; j < dkey_number; j++) {
			/* Print enumerated dkeys */
            		daos_key_t diov;
			snprintf(dkey, dkey_kds[j].kd_key_len + 1, "%s", ptr);
			d_iov_set(&diov, (void*)dkey, dkey_kds[j].kd_key_len);
			printf("j:%d dkey iov buf:%s len:%d\n", j, (char*)diov.iov_buf, (int)dkey_kds[j].kd_key_len);
			dkey_data_ptr = (char*) malloc((int)dkey_kds[j].kd_key_len * sizeof(char));
			memcpy(dkey_data_ptr, diov.iov_buf, (int)dkey_kds[j].kd_key_len);
			(*dk)[*dk_index].dkey_val.len = (int)dkey_kds[j].kd_key_len; 
			(*dk)[*dk_index].dkey_val.p = (void*)dkey_data_ptr; 
			ptr += dkey_kds[j].kd_key_len;

			/* loop to enumerate akeys */
			daos_anchor_t akey_anchor = {0}; 
			while (!daos_anchor_is_eof(&akey_anchor)) {

				d_sg_list_t     sgl;
				d_iov_t         iov;
				daos_key_desc_t akey_kds[ENUM_DESC_NR]       = {0};
				uint32_t        akey_number                  = ENUM_DESC_NR;
				char            akey_enum_buf[ENUM_DESC_BUF] = {0};
		                char 		akey[ENUM_KEY_BUF]           = {0};

				sgl.sg_nr     = 1;
				sgl.sg_nr_out = 0;
				sgl.sg_iovs   = &iov;

				d_iov_set(&iov, akey_enum_buf, ENUM_DESC_BUF);

				/* get akeys */
				rc = daos_obj_list_akey(*oh, DAOS_TX_NONE, &diov, &akey_number, akey_kds,
							&sgl, &akey_anchor, NULL);
				if (rc)
					return daos_der2errno(rc);       

				/* if no akeys returned move on */
				if (akey_number == 0)
					continue;
				*ak = realloc(*ak,  (akey_number + *total_akeys) * sizeof(akey_t));
				char *akey_data_ptr;
				int i;
				char* ptr;
				/* parse out individual akeys based on key length and numver of dkeys returned */
				for (ptr = akey_enum_buf, i = 0; i < akey_number; i++) {
					daos_key_t aiov;
					daos_iod_t iod;
					snprintf(akey, akey_kds[i].kd_key_len + 1, "%s", ptr);
					d_iov_set(&aiov, (void*)akey, akey_kds[i].kd_key_len);
					printf("\ti:%d akey:%s len:%d\n", i, (char*)aiov.iov_buf, (int)akey_kds[i].kd_key_len);

					akey_data_ptr = (char *)malloc((int)akey_kds[i].kd_key_len * sizeof(char));
					memcpy(akey_data_ptr, aiov.iov_buf, (int)akey_kds[i].kd_key_len);
					(*ak)[*ak_index].akey_val.len = (int)akey_kds[i].kd_key_len; 
					(*ak)[*ak_index].akey_val.p = (void*)akey_data_ptr; 

					/* set iod values */
					iod.iod_nr   = 1;
					iod.iod_type = DAOS_IOD_SINGLE;
					iod.iod_size = DAOS_REC_ANY;

					d_iov_set(&iod.iod_name, (void*)akey, strlen(akey));
					/* I meant with the probe that you do a fetch (with NULL sgl)
					* of single value type, and if that returns iod_size == 0, then
					* a single value does not exist.*/
					/* do fetch with sgl == NULL to check if iod type (ARRAY OR SINGLE VAL) */
					rc = daos_obj_fetch(*oh, DAOS_TX_NONE, 0, &diov, 1, &iod, NULL, NULL, NULL);

					/* if iod_size == 0 then this is a DAOS_IOD_ARRAY type */
					/* TODO: create a record dset for each
					 * akey */
					char rec_name[5];
					snprintf(rec_name, 5, "%lu", *ak_index);
					hsize_t rx_dims[1] = {0};
					hsize_t rx_max_dims[1] = {H5S_UNLIMITED};
					hid_t rx_dspace = H5Screate_simple(1, rx_dims, rx_max_dims);
					hid_t plist = H5Pcreate(H5P_DATASET_CREATE);
					H5Pset_layout(plist, H5D_CHUNKED);
					hsize_t rx_chunk_dims[1] = {100};
					H5Pset_chunk(plist, 1, rx_chunk_dims);
					hid_t rx_dset;
					if ((int)iod.iod_size == 0) {
						hid_t rx_dtype = H5Tcreate(H5T_OPAQUE, 1);
						H5Tset_tag(rx_dtype, "Opaque dtype");
						rx_dset = H5Dcreate(*file, rec_name, rx_dtype, rx_dspace,
								H5P_DEFAULT, plist, H5P_DEFAULT);
						(*ak)[*ak_index].rec_dset_id = rx_dset;
						H5Pclose(plist);
						H5Sclose(rx_dspace);
						rc = serialize_recx_array(&rx_dset, &rx_dspace,
									&diov, &aiov, oh, &iod);
						/* encode dataspace description
						 * in buffer then store in
						 * attribute on dataset */
						size_t nalloc;
						herr_t ret = H5Sencode(rx_dspace, NULL, &nalloc);
						/* get size of buffer needed
						 * from nalloc */
						unsigned char *buf = malloc(nalloc * sizeof(unsigned char));
						ret = H5Sencode(rx_dspace, buf, &nalloc);
						char attr_name[36];
						snprintf(attr_name, 36, "%d", rx_dset);
						hid_t selection_attribute;
						selection_attribute = H5Acreate2(rx_dset, attr_name, rx_dtype,
										rx_dspace, H5P_DEFAULT, H5P_DEFAULT);
						H5Awrite(selection_attribute, rx_dtype, buf);
						if (buf != NULL) 
							free(buf);
					} else {
						hid_t rx_dtype = H5Tcreate(H5T_OPAQUE, iod.iod_size);
						H5Tset_tag(rx_dtype, "Opaque dtype");
						rx_dset = H5Dcreate(*file, rec_name, rx_dtype, rx_dspace,
								H5P_DEFAULT, plist, H5P_DEFAULT);
						(*ak)[*ak_index].rec_dset_id = rx_dset;
						H5Pclose(plist);
						H5Sclose(rx_dspace);
						rc = serialize_recx_single(&rx_dset, &rx_dtype,
									&rx_dspace, &diov, oh, &iod);
					}
					/* advance to next akey returned */	
					ptr += akey_kds[i].kd_key_len;
					(*ak_index)++;
				}
				*total_akeys = (*total_akeys) + akey_number;
				*akey_offset = (*total_akeys) - akey_number;
				(*dk)[*dk_index].akey_offset = *akey_offset;
			}
			(*dk_index)++;
		}
		*total_dkeys = (*total_dkeys) + dkey_number;
		*dkey_offset = (*total_dkeys) - dkey_number;
	}
	return rc;
}

static int
copy_create_dest(struct cmd_args_s *ap, daos_cont_info_t *dst_cont_info)
{
	/* query layout type of source container, if dst container needs to be
	* created it uses the same layout type as the source */
	daos_prop_t		*prop_query;
	int 			rc;
	struct daos_prop_entry	*entry;
	char			type[10] = {};
	uint32_t		i;
	uint32_t		entry_type;

	if (uuid_is_null(ap->dst_cont_uuid))
		uuid_generate(ap->dst_cont_uuid);
	prop_query = daos_prop_alloc(DAOS_PROP_CO_NUM);
	if (prop_query == NULL) return -DER_NOMEM;
	entry_type = DAOS_PROP_CO_MIN + 1;
	for (i = 0; i < prop_query->dpp_nr; entry_type++) {
		prop_query->dpp_entries[i].dpe_type = entry_type;
		i++;
	}
	rc = daos_cont_query(ap->cont, NULL, prop_query, NULL);
	if (rc)
		fprintf(stderr, "Container query failed, result: %d\n", rc);
	entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_LAYOUT_TYPE);
	if (entry == NULL)
		fprintf(stderr, "layout type property not found\n");
	daos_unparse_ctype(entry->dpe_val, type);
	D_PRINT("layout type -> "DF_U64"/%s\n", entry->dpe_val, type);

	/* if cont open failed, try to create dst cont */
	if (strcmp(type, "POSIX") == 0) {
		dfs_attr_t attr;
		attr.da_id = 0;
		attr.da_oclass_id = ap->oclass;
		attr.da_chunk_size = ap->chunk_size;
		attr.da_props = ap->props;
		rc = dfs_cont_create(ap->pool, ap->dst_cont_uuid, &attr, NULL, NULL);
	} else {
		rc = daos_cont_create(ap->pool, ap->dst_cont_uuid, ap->props, NULL);
	}
	if (rc != 0)
		fprintf(stderr, "failed to create destination container: %d\n", rc);

	/* print out created cont uuid */
	fprintf(stdout, "Successfully created container "DF_UUIDF"\n", DP_UUID(ap->dst_cont_uuid));
	rc = daos_cont_open(ap->pool, ap->dst_cont_uuid, DAOS_COO_RW, &ap->dst_cont, dst_cont_info, NULL);
	return rc;
}

int
cont_copy_hdlr(struct cmd_args_s *ap)
{
	int rc;
	//printf("\tsrc pool UUID: "DF_UUIDF"\n", DP_UUID(ap->src_p_uuid));
	//printf("\tsrc cont UUID: "DF_UUIDF"\n", DP_UUID(ap->src_cont_uuid));
	//printf("\tdst pool UUID: "DF_UUIDF"\n", DP_UUID(ap->dst_p_uuid));
	//printf("\tdst cont UUID: "DF_UUIDF"\n", DP_UUID(ap->dst_cont_uuid));
	//printf("\tsrc svc: "DF_UUIDF"\n", DP_UUID(ap->src_svc));
	//printf("\tdst svc: "DF_UUIDF"\n", DP_UUID(ap->dst_svc));
	printf("\tsrc path: %s\n", ap->src_path);
	printf("\tdst path: %s\n", ap->dst_path);
        //exit(0);
	daos_cont_info_t	src_cont_info;
	daos_cont_info_t	dst_cont_info;

	struct duns_attr_t dst_dattr = {0};
	struct duns_attr_t src_dattr = {0};
        if (ap->src_path != NULL) {
		/* Resolve pool, container UUIDs from path if needed */
		rc = duns_resolve_path(ap->src_path, &src_dattr);
		if (rc) {
			fprintf(stderr, "could not resolve pool, container "
					"by path: %s\n", ap->src_path);
			//D_GOTO(out, rc);
		}
		ap->type = src_dattr.da_type;
		uuid_copy(ap->src_p_uuid, src_dattr.da_puuid);
		uuid_copy(ap->src_cont_uuid, src_dattr.da_cuuid);
	}

        if (ap->dst_path != NULL) {
		/* Resolve pool, container UUIDs from path if needed */
		rc = duns_resolve_path(ap->dst_path, &dst_dattr);
		if (rc) {
			fprintf(stderr, "could not resolve pool, container "
					"by path: %s\n", ap->dst_path);
			//D_GOTO(out, rc);
		}
		ap->type = dst_dattr.da_type;
		uuid_copy(ap->dst_p_uuid, dst_dattr.da_puuid);
		uuid_copy(ap->dst_cont_uuid, dst_dattr.da_cuuid);
	}

	/* connect to source pool */
	rc = daos_pool_connect(ap->src_p_uuid, ap->sysname, ap->src_svc,
			DAOS_PC_RW, &ap->pool, NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
	}
	/* open source container */
	rc = daos_cont_open(ap->pool, ap->src_cont_uuid, DAOS_COO_RW,
		&ap->cont, &src_cont_info, NULL);
	if (rc != 0) {
		fprintf(stderr, "src cont open failed: %d\n", rc);
	}

	/* if given source and destination pools are different, then connect
	 * to the destination pool */
	if (uuid_compare(ap->src_p_uuid, ap->dst_p_uuid) != 0) {
		rc = daos_pool_connect(ap->dst_p_uuid, ap->sysname, ap->dst_svc,
		DAOS_PC_RW, &ap->dst_pool, NULL /* info */, NULL /* ev */);
		if (rc != 0) {
			fprintf(stderr, "failed to connect to destination pool: %d\n", rc);
		}
		if (daos_uuid_valid(ap->dst_cont_uuid)) { 
			rc = daos_cont_open(ap->dst_pool, ap->dst_cont_uuid, DAOS_COO_RW,
				&ap->dst_cont, &dst_cont_info, NULL);
		}
	} else {
		/* othersize the source and destination container are in the same pool */
		if (daos_uuid_valid(ap->dst_cont_uuid)) { 
			rc = daos_cont_open(ap->pool, ap->dst_cont_uuid, DAOS_COO_RW,
				&ap->dst_cont, &dst_cont_info, NULL);
		} else {
			copy_create_dest(ap, &dst_cont_info);
		}
	}

	/* List objects in src container to be copied to 
	* destination container */
	static const int OID_ARR_SIZE = 50;
 	daos_obj_id_t	 oids[OID_ARR_SIZE];
 	daos_anchor_t	 anchor;
 	uint32_t	 oids_nr;
 	daos_handle_t	 toh;
 	daos_epoch_t	 epoch;
	uint32_t         total = 0;

	rc = daos_cont_create_snap(ap->cont, &epoch, NULL, NULL);
	if (rc)
		fprintf(stderr, "failed to create snapshot\n");	

	rc = daos_cont_open_oit(ap->cont, epoch, &toh, NULL);
 	D_ASSERT(rc == 0);

 	memset(&anchor, 0, sizeof(anchor));
	while (1) {
 		oids_nr = OID_ARR_SIZE;
 		rc = daos_cont_list_oit(toh, oids, &oids_nr, &anchor, NULL);
 		//D_ASSERT(rc == 0, "%d\n", rc);
 		D_PRINT("returned %d oids\n", oids_nr);
		int i;

		/* list object ID's */
 		for (i = 0; i < oids_nr; i++) {
 			//D_PRINT("oid[%d] ="DF_OID"\n", total, DP_OID(oids[i]));
			/* open DAOS object based on oid[i] to get obj handle */
			daos_handle_t oh;
			rc = daos_obj_open(ap->cont, oids[i], 0, &oh, NULL);

			/* open handle of object in dst container */
			daos_handle_t dst_oh;
			rc = daos_obj_open(ap->dst_cont, oids[i], 0, &dst_oh, NULL);
			rc = copy_list_keys(&oh, &dst_oh);

			/* close source and destination object */
                       	daos_obj_close(oh, NULL);
                       	daos_obj_close(dst_oh, NULL);
 			total++;
	        }

 		if (daos_anchor_is_eof(&anchor)) {
 			//D_PRINT("done\n");
 			break;
 		}
	}

	/* close object iterator */
 	rc = daos_cont_close_oit(toh, NULL);
	daos_epoch_range_t epr;
	epr.epr_lo = epoch;
	epr.epr_hi = epoch;
	rc = daos_cont_destroy_snap(ap->cont, epr, NULL);
	D_ASSERT(rc == 0);

	/* Container close in normal and error flows: preserve rc */
	rc = daos_cont_close(ap->cont, NULL);
	if (rc != 0)
		fprintf(stderr, "src container close failed: %d\n", rc);

	rc = daos_cont_close(ap->dst_cont, NULL);
	if (rc != 0)
		fprintf(stderr, "dst container close failed: %d\n", rc);

	/* Pool disconnect in normal and error flows: preserve rc */
	rc = daos_pool_disconnect(ap->pool, NULL);
	if (rc != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc);

	/* if source and dst pool were different need to disconnect
         * from dst too */
	if (uuid_compare(ap->src_p_uuid, ap->dst_p_uuid) != 0) {
		rc = daos_pool_disconnect(ap->dst_pool, NULL);
		if (rc != 0)
			fprintf(stderr, "dst Pool disconnect failed : %d\n", rc);
	}
	return rc;
}

int
cont_serialize_hdlr(struct cmd_args_s *ap)
{
	int rc;
	printf("\tpool UUID: "DF_UUIDF"\n", DP_UUID(ap->p_uuid));
	printf("\tcont UUID: "DF_UUIDF"\n", DP_UUID(ap->c_uuid));
	printf("\tsvc: "DF_UUIDF"\n", DP_UUID(ap->mdsrv));
	daos_cont_info_t	cont_info;

	struct duns_attr_t dattr = {0};
        if (ap->path != NULL) {
		/* Resolve pool, container UUIDs from path if needed */
		rc = duns_resolve_path(ap->path, &dattr);
		if (rc) {
			fprintf(stderr, "could not resolve pool, container "
					"by path: %s\n", ap->path);
			//D_GOTO(out, rc);
		}
		ap->type = dattr.da_type;
		uuid_copy(ap->p_uuid, dattr.da_puuid);
	}

	/* connect to source pool */
	rc = daos_pool_connect(ap->p_uuid, ap->sysname, ap->mdsrv,
			DAOS_PC_RW, &ap->pool, NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
	}
	/* open source container */
	rc = daos_cont_open(ap->pool, ap->c_uuid, DAOS_COO_RW,
		&ap->cont, &cont_info, NULL);
	if (rc != 0) {
		fprintf(stderr, "src cont open failed: %d\n", rc);
	}

	/* TODO: setup HDF5 */
	/* create h5 file */
	char *ftype = ".h5";
	char filename[64];
	snprintf(filename, 64, "%s", DP_UUID(ap->c_uuid));
	strcat(filename, ftype);
	printf("Serializing Container "DF_UUIDF" to "DF_UUIDF".h5\n",
		DP_UUID(ap->c_uuid), DP_UUID(ap->c_uuid));

	hid_t file;
	file = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);

	/* OID Data */
	hid_t oid_memtype;
	hid_t oid_dspace;
	hid_t oid_dset;
	
	oid_memtype = H5Tcreate (H5T_COMPOUND, sizeof(oid_t));
	H5Tinsert (oid_memtype, "OID Hi", HOFFSET (oid_t, oid_hi), H5T_NATIVE_UINT64);
	H5Tinsert (oid_memtype, "OID Low", HOFFSET (oid_t, oid_low), H5T_NATIVE_UINT64);
	H5Tinsert (oid_memtype, "Dkey Offset", HOFFSET (oid_t, dkey_offset), H5T_NATIVE_UINT64);

	/* DKEY Data */
	hid_t dkey_memtype;
	hid_t dkey_vtype;
	hid_t dkey_dspace;
	hid_t dkey_dset;
	dkey_memtype = H5Tcreate(H5T_COMPOUND, sizeof(dkey_t));
	dkey_vtype = H5Tvlen_create(H5T_NATIVE_CHAR);
	H5Tinsert(dkey_memtype, "Akey Offset",
	HOFFSET(dkey_t, akey_offset), H5T_NATIVE_UINT64);
	H5Tinsert(dkey_memtype, "Dkey Value", HOFFSET(dkey_t, dkey_val), dkey_vtype);
								
	/* AKEY Data */
	hid_t akey_memtype;
	hid_t akey_vtype;
	hid_t akey_dspace;
	hid_t akey_dset;
	akey_memtype = H5Tcreate(H5T_COMPOUND, sizeof(akey_t));
	akey_vtype = H5Tvlen_create(H5T_NATIVE_CHAR);
	H5Tinsert(akey_memtype, "Dataset ID",
		HOFFSET(akey_t, rec_dset_id), H5T_NATIVE_UINT64);
	H5Tinsert(akey_memtype, "Akey Value", HOFFSET(akey_t, akey_val), akey_vtype);
								
	/* List objects in src container to be copied to 
	* destination container */
	static const int OID_ARR_SIZE = 50;
 	daos_obj_id_t	 oids[OID_ARR_SIZE];
 	daos_anchor_t	 anchor;
 	uint32_t	 oids_nr;
 	daos_handle_t	 toh;
 	daos_epoch_t	 epoch;
	uint32_t         total = 0;

	rc = daos_cont_create_snap(ap->cont, &epoch, NULL, NULL);
	if (rc)
		fprintf(stderr, "failed to create snapshot\n");	

	rc = daos_cont_open_oit(ap->cont, epoch, &toh, NULL);
 	D_ASSERT(rc == 0);

 	memset(&anchor, 0, sizeof(anchor));
	while (1) {
 		oids_nr = OID_ARR_SIZE;
 		rc = daos_cont_list_oit(toh, oids, &oids_nr, &anchor, NULL);
 		//D_ASSERT(rc == 0, "%d\n", rc);
 		D_PRINT("returned %d oids\n", oids_nr);

		int64_t oid_nr = oids_nr;
		hsize_t oid_dims[1] = {oid_nr};

		oid_dspace = H5Screate_simple(1, oid_dims, NULL);
		oid_dset = H5Dcreate(file, "Oid Data", oid_memtype, oid_dspace, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
		uint64_t total_dkeys = 0;
		uint64_t total_akeys = 0;
		oid_t *oid_data = malloc(oid_nr * sizeof(oid_t));
		dkey_t *dkey_data = malloc(sizeof(dkey_t));
		akey_t *akey_data = malloc(sizeof(akey_t));
		uint64_t dk_index = 0;
		uint64_t ak_index = 0;
		dkey_t **dk = &dkey_data;
		akey_t **ak = &akey_data;

		int i;
		/* list object ID's */
 		for (i = 0; i < oids_nr; i++) {
 			D_PRINT("oid[%d] ="DF_OID"\n", total, DP_OID(oids[i]));
			/* open DAOS object based on oid[i] to get obj handle */
			daos_handle_t oh;

		        uint64_t dkey_offset = 0;
		        uint64_t akey_offset = 0;
			oid_data[i].oid_hi = oids[i].hi;
			oid_data[i].oid_low = oids[i].lo;

			rc = daos_obj_open(ap->cont, oids[i], 0, &oh, NULL);

			rc = serialize_list_keys(&file, dk, &dk_index, ak, &ak_index,
						&dkey_offset, &akey_offset,
						&total_dkeys, &total_akeys, &oh);

			oid_data[i].dkey_offset = dkey_offset;
			printf("oid[%d] dkey offset: %lu\n", i, oid_data[i].dkey_offset);
			/* close source and destination object */
                       	daos_obj_close(oh, NULL);
 			total++;
	        }

	        printf("total dkeys: %lu\n", total_dkeys);
	        printf("total akeys: %lu\n", total_akeys);
		hsize_t dkey_dims[1] = {total_dkeys};     
		dkey_dspace = H5Screate_simple(1, dkey_dims, NULL);
		dkey_dset = H5Dcreate(file, "Dkey Data", dkey_memtype, dkey_dspace, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

		hsize_t akey_dims[1] = {total_akeys};     
		akey_dspace = H5Screate_simple(1, akey_dims, NULL);
		akey_dset = H5Dcreate(file, "Akey Data", akey_memtype, akey_dspace, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

		hid_t status = H5Dwrite(oid_dset, oid_memtype, H5S_ALL, H5S_ALL, H5P_DEFAULT, oid_data);
		printf("STATUS oid data write: %d\n", (int)status);
		status = H5Dwrite(dkey_dset, dkey_memtype, H5S_ALL, H5S_ALL, H5P_DEFAULT, (*dk));
		printf("STATUS dkey data write: %d\n", (int)status);
		H5Dwrite(akey_dset, akey_memtype, H5S_ALL, H5S_ALL, H5P_DEFAULT, akey_data);

		H5Dclose(oid_dset);
		H5Dclose(dkey_dset);
		H5Dclose(akey_dset);
		H5Sclose(oid_dspace);
		H5Sclose(dkey_dspace);
		H5Sclose(akey_dspace);
		H5Tclose(oid_memtype);
		H5Tclose(dkey_memtype);
		H5Tclose(akey_memtype);

		if (oid_data != NULL)
			free(oid_data);
		if (dkey_data != NULL)
			free(dkey_data);
		if (akey_data != NULL)
			free(akey_data);
 		if (daos_anchor_is_eof(&anchor)) {
 			//D_PRINT("done\n");
 			break;
 		}
	}

	/* close object iterator */
 	rc = daos_cont_close_oit(toh, NULL);
	daos_epoch_range_t epr;
	epr.epr_lo = epoch;
	epr.epr_hi = epoch;
	rc = daos_cont_destroy_snap(ap->cont, epr, NULL);
	D_ASSERT(rc == 0);

	return rc;
}


static int
print_acl(FILE *outstream, daos_prop_t *acl_prop, bool verbose)
{
	int			rc = 0;
	struct daos_prop_entry	*entry;
	struct daos_acl		*acl = NULL;
	char			**acl_str = NULL;
	size_t			nr_acl_str;
	char			verbose_str[DAOS_ACL_MAX_ACE_STR_LEN * 2];
	size_t			i;

	/*
	 * Validate the ACL before we start printing anything out.
	 */
	entry = daos_prop_entry_get(acl_prop, DAOS_PROP_CO_ACL);
	if (entry != NULL && entry->dpe_val_ptr != NULL) {
		acl = entry->dpe_val_ptr;
		rc = daos_acl_to_strs(acl, &acl_str, &nr_acl_str);
		if (rc != 0) {
			fprintf(stderr,
				"Invalid ACL cannot be displayed\n");
			return rc;
		}
	}

	entry = daos_prop_entry_get(acl_prop, DAOS_PROP_CO_OWNER);
	if (entry != NULL && entry->dpe_str != NULL)
		fprintf(outstream, "# Owner: %s\n", entry->dpe_str);

	entry = daos_prop_entry_get(acl_prop, DAOS_PROP_CO_OWNER_GROUP);
	if (entry != NULL && entry->dpe_str != NULL)
		fprintf(outstream, "# Owner-Group: %s\n", entry->dpe_str);

	fprintf(outstream, "# Entries:\n");

	if (acl == NULL || acl->dal_len == 0) {
		fprintf(outstream, "#   None\n");
		return 0;
	}

	for (i = 0; i < nr_acl_str; i++) {
		if (verbose) {
			rc = daos_ace_str_get_verbose(acl_str[i], verbose_str,
						      sizeof(verbose_str));
			/*
			 * If the ACE is invalid, we'll still print it out -
			 * we just can't parse it to any helpful verbose string.
			 */
			if (rc != -DER_INVAL)
				fprintf(outstream, "# %s\n", verbose_str);
		}
		fprintf(outstream, "%s\n", acl_str[i]);
	}

	return 0;
}

int
cont_get_acl_hdlr(struct cmd_args_s *ap)
{
	int		rc;
	daos_prop_t	*prop = NULL;
	struct stat	sb;
	FILE		*outstream = stdout;

	if (ap->outfile) {
		if (!ap->force && (stat(ap->outfile, &sb) == 0)) {
			fprintf(stderr,
				"Unable to create output file: File already "
				"exists\n");
			return -DER_EXIST;
		}

		outstream = fopen(ap->outfile, "w");
		if (outstream == NULL) {
			fprintf(stderr, "Unable to create output file: %s\n",
				strerror(errno));
			return daos_errno2der(errno);
		}
	}

	rc = daos_cont_get_acl(ap->cont, &prop, NULL);
	if (rc != 0) {
		fprintf(stderr, "failed to get ACL for container: %d\n", rc);
	} else {
		rc = print_acl(outstream, prop, ap->verbose);
		if (ap->outfile)
			fprintf(stdout, "Wrote ACL to output file: %s\n",
				ap->outfile);
	}

	if (ap->outfile)
		fclose(outstream);
	daos_prop_free(prop);
	return rc;
}

/*
 * Returns a substring of the line with leading and trailing whitespace trimmed.
 * Doesn't allocate any new memory - trimmed string is just a pointer.
 */
static char *
trim_acl_file_line(char *line)
{
	char *end;

	while (isspace(*line))
		line++;
	if (line[0] == '\0')
		return line;

	end = line + strnlen(line, DAOS_ACL_MAX_ACE_STR_LEN) - 1;
	while (isspace(*end))
		end--;
	end[1] = '\0';

	return line;
}

static int
parse_acl_file(const char *path, struct daos_acl **acl)
{
	int		rc = 0;
	FILE		*instream;
	char		*line = NULL;
	size_t		line_len = 0;
	char		*trimmed;
	struct daos_ace	*ace;
	struct daos_acl	*tmp_acl;

	instream = fopen(path, "r");
	if (instream == NULL) {
		fprintf(stderr, "Unable to read ACL input file '%s': %s\n",
			path, strerror(errno));
		return daos_errno2der(errno);
	}

	tmp_acl = daos_acl_create(NULL, 0);
	if (tmp_acl == NULL) {
		fprintf(stderr, "Unable to allocate memory for ACL\n");
		D_GOTO(out, rc = -DER_NOMEM);
	}

	while (getline(&line, &line_len, instream) != -1) {
		trimmed = trim_acl_file_line(line);

		/* ignore blank lines and comments */
		if (trimmed[0] == '\0' || trimmed[0] == '#') {
			D_FREE(line);
			continue;
		}

		rc = daos_ace_from_str(trimmed, &ace);
		if (rc != 0) {
			fprintf(stderr,
				"Error parsing ACE '%s' from file: %s (%d)\n",
				trimmed, d_errstr(rc), rc);
			D_GOTO(parse_err, rc);
		}

		rc = daos_acl_add_ace(&tmp_acl, ace);
		daos_ace_free(ace);
		if (rc != 0) {
			fprintf(stderr, "Error parsing ACL file: %s (%d)\n",
				d_errstr(rc), rc);
			D_GOTO(parse_err, rc);
		}

		D_FREE(line);
	}

	if (daos_acl_validate(tmp_acl) != 0) {
		fprintf(stderr, "Content of ACL file is invalid\n");
		D_GOTO(parse_err, rc = -DER_INVAL);
	}

	*acl = tmp_acl;
	D_GOTO(out, rc = 0);

parse_err:
	D_FREE(line);
	daos_acl_free(tmp_acl);
out:
	fclose(instream);
	return rc;
}

int
cont_overwrite_acl_hdlr(struct cmd_args_s *ap)
{
	int		rc;
	struct daos_acl	*acl = NULL;
	daos_prop_t	*prop_out;

	if (!ap->aclfile) {
		fprintf(stderr,
			"Parameter --acl-file is required\n");
		return -DER_INVAL;
	}

	rc = parse_acl_file(ap->aclfile, &acl);
	if (rc != 0)
		return rc;

	rc = daos_cont_overwrite_acl(ap->cont, acl, NULL);
	daos_acl_free(acl);
	if (rc != 0) {
		fprintf(stderr,
			"failed to overwrite ACL for container: %d\n", rc);
		return rc;
	}

	rc = daos_cont_get_acl(ap->cont, &prop_out, NULL);
	if (rc != 0) {
		fprintf(stderr,
			"overwrite appeared to succeed, but cannot fetch ACL "
			"for confirmation: %d\n", rc);
		return rc;
	}

	rc = print_acl(stdout, prop_out, false);


	daos_prop_free(prop_out);
	return rc;
}

int
cont_update_acl_hdlr(struct cmd_args_s *ap)
{
	int		rc;
	struct daos_acl	*acl = NULL;
	struct daos_ace	*ace = NULL;
	daos_prop_t	*prop_out;

	/* need one or the other, not both */
	if (!ap->aclfile == !ap->entry) {
		fprintf(stderr,
			"either parameter --acl-file or --entry is required\n");
		return -DER_INVAL;
	}

	if (ap->aclfile) {
		rc = parse_acl_file(ap->aclfile, &acl);
		if (rc != 0)
			return rc;
	} else {
		rc = daos_ace_from_str(ap->entry, &ace);
		if (rc != 0) {
			fprintf(stderr, "failed to parse entry: %d\n", rc);
			return rc;
		}

		acl = daos_acl_create(&ace, 1);
		daos_ace_free(ace);
		if (acl == NULL) {
			fprintf(stderr, "failed to make ACL from entry: %d\n",
				rc);
			return rc;
		}
	}

	rc = daos_cont_update_acl(ap->cont, acl, NULL);
	daos_acl_free(acl);
	if (rc != 0) {
		fprintf(stderr,
			"failed to update ACL for container: %d\n", rc);
		return rc;
	}

	rc = daos_cont_get_acl(ap->cont, &prop_out, NULL);
	if (rc != 0) {
		fprintf(stderr,
			"update appeared to succeed, but cannot fetch ACL "
			"for confirmation: %d\n", rc);
		return rc;
	}

	rc = print_acl(stdout, prop_out, false);

	daos_prop_free(prop_out);
	return rc;
}

int
cont_delete_acl_hdlr(struct cmd_args_s *ap)
{
	int				rc;
	enum daos_acl_principal_type	type;
	char				*name;
	daos_prop_t			*prop_out;

	if (!ap->principal) {
		fprintf(stderr,
			"parameter --principal is required\n");
		return -DER_INVAL;
	}

	rc = daos_acl_principal_from_str(ap->principal, &type, &name);
	if (rc != 0) {
		fprintf(stderr, "unable to parse principal string '%s': %d\n",
			ap->principal, rc);
		return rc;
	}

	rc = daos_cont_delete_acl(ap->cont, type, name, NULL);
	D_FREE(name);
	if (rc != 0) {
		fprintf(stderr,
			"failed to delete ACL entry for container: %d\n", rc);
		return rc;
	}

	rc = daos_cont_get_acl(ap->cont, &prop_out, NULL);
	if (rc != 0) {
		fprintf(stderr,
			"delete appeared to succeed, but cannot fetch ACL "
			"for confirmation: %d\n", rc);
		return rc;
	}

	rc = print_acl(stdout, prop_out, false);

	daos_prop_free(prop_out);
	return rc;
}

int
cont_set_owner_hdlr(struct cmd_args_s *ap)
{
	int	rc;

	if (!ap->user && !ap->group) {
		fprintf(stderr,
			"parameter --user or --group is required\n");
		return -DER_INVAL;
	}

	rc = daos_cont_set_owner(ap->cont, ap->user, ap->group, NULL);
	if (rc != 0) {
		fprintf(stderr,
			"failed to set owner for container: %d\n", rc);
		return rc;
	}

	fprintf(stdout, "successfully updated owner for container\n");
	return rc;
}

int
obj_query_hdlr(struct cmd_args_s *ap)
{
	struct daos_obj_layout *layout;
	int			i;
	int			j;
	int			rc;

	rc = daos_obj_layout_get(ap->cont, ap->oid, &layout);
	if (rc) {
		fprintf(stderr, "daos_obj_layout_get failed, rc: %d\n", rc);
		D_GOTO(out, rc);
	}

	/* Print the object layout */
	fprintf(stdout, "oid: "DF_OID" ver %d grp_nr: %d\n", DP_OID(ap->oid),
		layout->ol_ver, layout->ol_nr);

	for (i = 0; i < layout->ol_nr; i++) {
		struct daos_obj_shard *shard;

		shard = layout->ol_shards[i];
		fprintf(stdout, "grp: %d\n", i);
		for (j = 0; j < shard->os_replica_nr; j++)
			fprintf(stdout, "replica %d %d\n", j,
				shard->os_ranks[j]);
	}

	daos_obj_layout_free(layout);

out:
	return rc;
}
