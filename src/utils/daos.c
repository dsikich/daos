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
/**
 * daos(8): DAOS Container and Object Management Utility
 */

#define D_LOGFAC	DD_FAC(client)

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <daos.h>
#include <daos/common.h>
#include <daos/rpc.h>
#include <daos/debug.h>
#include <daos/object.h>
#include <sys/stat.h>
#include "daos_types.h"
#include "daos_api.h"
#include "daos_fs.h"
#include "daos_uns.h"
#include "daos_hdlr.h"

const char		*default_sysname = DAOS_DEFAULT_SYS_NAME;
static enum copy_op
copy_op_parse(const char *str)
{
	if (strcmp(str, "cont") == 0)
		return COPY_CONT;
	return -1;
}

static enum cont_op
cont_op_parse(const char *str)
{
	if (strcmp(str, "create") == 0)
		return CONT_CREATE;
	else if (strcmp(str, "destroy") == 0)
		return CONT_DESTROY;
	else if (strcmp(str, "list-objects") == 0)
		return CONT_LIST_OBJS;
	else if (strcmp(str, "list-obj") == 0)
		return CONT_LIST_OBJS;
	else if (strcmp(str, "query") == 0)
		return CONT_QUERY;
	else if (strcmp(str, "stat") == 0)
		return CONT_STAT;
	else if (strcmp(str, "get-prop") == 0)
		return CONT_GET_PROP;
	else if (strcmp(str, "set-prop") == 0)
		return CONT_SET_PROP;
	else if (strcmp(str, "list-attrs") == 0)
		return CONT_LIST_ATTRS;
	else if (strcmp(str, "del-attr") == 0)
		return CONT_DEL_ATTR;
	else if (strcmp(str, "get-attr") == 0)
		return CONT_GET_ATTR;
	else if (strcmp(str, "set-attr") == 0)
		return CONT_SET_ATTR;
	else if (strcmp(str, "create-snap") == 0)
		return CONT_CREATE_SNAP;
	else if (strcmp(str, "list-snaps") == 0)
		return CONT_LIST_SNAPS;
	else if (strcmp(str, "destroy-snap") == 0)
		return CONT_DESTROY_SNAP;
	else if (strcmp(str, "rollback") == 0)
		return CONT_ROLLBACK;
	else if (strcmp(str, "get-acl") == 0)
		return CONT_GET_ACL;
	else if (strcmp(str, "overwrite-acl") == 0)
		return CONT_OVERWRITE_ACL;
	else if (strcmp(str, "update-acl") == 0)
		return CONT_UPDATE_ACL;
	else if (strcmp(str, "delete-acl") == 0)
		return CONT_DELETE_ACL;
	else if (strcmp(str, "set-owner") == 0)
		return CONT_SET_OWNER;
	return -1;
}

/* Pool operations read-only here. See dmg for full pool management */
static enum pool_op
pool_op_parse(const char *str)
{
	if (strcmp(str, "list-containers") == 0)
		return POOL_LIST_CONTAINERS;
	else if (strcmp(str, "list-cont") == 0)
		return POOL_LIST_CONTAINERS;
	else if (strcmp(str, "query") == 0)
		return POOL_QUERY;
	else if (strcmp(str, "stat") == 0)
		return POOL_STAT;
	else if (strcmp(str, "get-prop") == 0)
		return POOL_GET_PROP;
	else if (strcmp(str, "get-attr") == 0)
		return POOL_GET_ATTR;
	else if (strcmp(str, "set-attr") == 0)
		return POOL_SET_ATTR;
	else if (strcmp(str, "list-attrs") == 0)
		return POOL_LIST_ATTRS;
	return -1;
}

static enum obj_op
obj_op_parse(const char *str)
{
	if (strcmp(str, "query") == 0)
		return OBJ_QUERY;
	else if (strcmp(str, "list-keys") == 0)
		return OBJ_LIST_KEYS;
	else if (strcmp(str, "dump") == 0)
		return OBJ_DUMP;
	return -1;
}

static void
cmd_args_print(struct cmd_args_s *ap)
{
	char	oclass[10] = {}, type[10] = {};

	if (ap == NULL)
		return;

	daos_oclass_id2name(ap->oclass, oclass);
	daos_unparse_ctype(ap->type, type);

	D_INFO("\tDAOS system name: %s\n", ap->sysname);
	D_INFO("\tpool UUID: "DF_UUIDF"\n", DP_UUID(ap->p_uuid));
	D_INFO("\tcont UUID: "DF_UUIDF"\n", DP_UUID(ap->c_uuid));

	D_INFO("\tpool svc: parsed %u ranks from input %s\n",
		ap->mdsrv ? ap->mdsrv->rl_nr : 0,
		ap->mdsrv_str ? ap->mdsrv_str : "NULL");

	D_INFO("\tattr: name=%s, value=%s\n",
		ap->attrname_str ? ap->attrname_str : "NULL",
		ap->value_str ? ap->value_str : "NULL");

	D_INFO("\tpath=%s, type=%s, oclass=%s, chunk_size="DF_U64"\n",
		ap->path ? ap->path : "NULL",
		type, oclass, ap->chunk_size);
	D_INFO("\tsnapshot: name=%s, epoch="DF_U64", epoch range=%s "
		"("DF_U64"-"DF_U64")\n",
		ap->snapname_str ? ap->snapname_str : "NULL",
		ap->epc,
		ap->epcrange_str ? ap->epcrange_str : "NULL",
		ap->epcrange_begin, ap->epcrange_end);
	D_INFO("\toid: "DF_OID"\n", DP_OID(ap->oid));
}

static daos_size_t
tobytes(const char *str)
{
	daos_size_t	 size;
	char		*end;

	if (str == NULL) {
		fprintf(stderr, "passed NULL string\n");
		return 0;
	}

	size = strtoull(str, &end, 0);
	/* Prevent negative numbers from turning into unsigned */
	if (str[0] == '-') {
		fprintf(stderr, "WARNING bytes < 0 (string %s)"
				"converted to "DF_U64" : using 0 instead\n",
				str, size);
		size = 0;
		return size;
	}

	/** no suffix used */
	if (*end == '\0')
		return size;

	/** let's be permissive and allow MB, Mb, mb ...*/
	if (*(end + 1) != '\0' &&
	    ((*(end + 1) != 'b' && *(end + 1) != 'B') || (*(end + 2) != '\0')))
		return 0;

	switch (*end) {
	case 'b':
	case 'B':
		break;
	case 'k':
	case 'K':
		size <<= 10;
		break;
	case 'm':
	case 'M':
		size <<= 20;
		break;
	case 'g':
	case 'G':
		size <<= 30;
		break;
	case 't':
	case 'T':
		size <<= 40;
		break;
	case 'p':
	case 'P':
		size <<= 50;
		break;
	case 'e':
	case 'E':
		size <<= 60;
		break;
	default:
		return 0;
	}

	return size;
}


static int
epoch_range_parse(struct cmd_args_s *ap)
{
	int		rc;
	long long int	parsed_begin = 0;
	long long int	parsed_end = 0;

	rc = sscanf(ap->epcrange_str, "%lld-%lld",
			&parsed_begin, &parsed_end);
	if ((rc != 2) || (parsed_begin < 0) || (parsed_end < 0))
		D_GOTO(out_invalid_format, -1);

	ap->epcrange_begin = parsed_begin;
	ap->epcrange_end = parsed_end;

	return 0;

out_invalid_format:
	fprintf(stderr, "epcrange=%s must be in A-B form\n",
		ap->epcrange_str);
	return -1;
}

/* oid str: oid_hi.oid_lo */
static int
daos_obj_id_parse(const char *oid_str, daos_obj_id_t *oid)
{
	const char *ptr = oid_str;
	char *end;
	uint64_t hi = 0;
	uint64_t lo = 0;

	/* parse hi
	 * errors if: negative numbers, no digits, exceeds maximum value
	 */
	hi = strtoull(ptr, &end, 10);
	if (ptr[0] == '-')
		return -1;
	if ((hi == 0) && (end == ptr))
		return -1;
	if ((hi == ULLONG_MAX) && (errno == ERANGE))
		return -1;

	/* parse lo after the '.' */
	if (*end != '.')
		return -1;

	ptr = end+1;

	lo = strtoull(ptr, &end, 10);
	if (ptr[0] == '-')
		return -1;
	if ((lo == 0) && (end == ptr))
		return -1;
	if ((lo == ULLONG_MAX) && (errno == ERANGE))
		return -1;

	oid->hi = hi;
	oid->lo = lo;

	return 0;
}

/* supported properties names are "label", "cksum" ("off" or <type> in
 * crc[16,32,64], sha1), "cksum_size", "srv_cksum" (cksum on server,
 * "on"/"off"), "red_factor" (redundancy factor, rf[0-4]).
 */
static int
daos_parse_property(char *name, char *value, daos_prop_t *props)
{
	/* dpp_nr is used to iterate in props here */
	struct daos_prop_entry *entry = &props->dpp_entries[props->dpp_nr];

	if (!strcmp(name, "label")) {
		size_t len = strnlen(value, DAOS_PROP_LABEL_MAX_LEN);

		if (len == DAOS_PROP_LABEL_MAX_LEN) {
			fprintf(stderr, "label string exceed %u bytes\n",
				DAOS_PROP_LABEL_MAX_LEN);
			return -DER_INVAL;
		}
		entry->dpe_type = DAOS_PROP_CO_LABEL;
		entry->dpe_str = strdup(value);
	} else if (!strcmp(name, "cksum")) {
		if (!strcmp(value, "off"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_OFF;
		else if (!strcmp(value, "crc16"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_CRC16;
		else if (!strcmp(value, "crc32"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_CRC32;
		else if (!strcmp(value, "crc64"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_CRC64;
		else if (!strcmp(value, "sha1")) {
			/* entry->dpe_val = DAOS_PROP_CO_CSUM_SHA1; */
			fprintf(stderr, "'sha1' isn't supported yet, please use one of the CRC option\n");
			return -DER_INVAL;
		} else {
			/* fprintf(stderr, "curently supported checksum types are 'off, crc[16,32,64], sha1'\n"); */
			fprintf(stderr, "curently supported checksum types are 'off, crc[16,32,64]'\n");
			return -DER_INVAL;
		}
		entry->dpe_type = DAOS_PROP_CO_CSUM;
	} else if (!strcmp(name, "cksum_size")) {
		char *endp;
		long val;

		/* use base 0 to interpret 0/octal or 0x/hex prefixes
		 * no need to check empty value, this is done in
		 * daos_parse_properties()
		 */
		val = strtoull(value, &endp, 0);
		if (*endp != '\0') {
			fprintf(stderr, "invalid digits in %s\n", value);
			return -DER_INVAL;
		} else if (val == ULLONG_MAX) {
			fprintf(stderr, "too big value %s\n", value);
			return -DER_INVAL;
		}

		entry->dpe_type = DAOS_PROP_CO_CSUM_CHUNK_SIZE;
		entry->dpe_val = val;
	} else if (!strcmp(name, "srv_cksum")) {
		if (!strcmp(value, "on"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_SV_ON;
		else if (!strcmp(value, "off"))
			entry->dpe_val = DAOS_PROP_CO_CSUM_SV_OFF;
		else {
			fprintf(stderr, "srv_cksum prop value can only be 'on/off'\n");
			return -DER_INVAL;
		}
		entry->dpe_type = DAOS_PROP_CO_CSUM_SERVER_VERIFY;
	} else if (!strcmp(name, "rf")) {
		if (!strcmp(value, "0"))
			entry->dpe_val = DAOS_PROP_CO_REDUN_RF0;
		else if (!strcmp(value, "1"))
			entry->dpe_val = DAOS_PROP_CO_REDUN_RF1;
		else if (!strcmp(value, "2"))
			entry->dpe_val = DAOS_PROP_CO_REDUN_RF2;
		else if (!strcmp(value, "3"))
			entry->dpe_val = DAOS_PROP_CO_REDUN_RF3;
		else if (!strcmp(value, "4"))
			entry->dpe_val = DAOS_PROP_CO_REDUN_RF4;
		else {
			fprintf(stderr, "presently supported redundancy factors (rf) are [0-4]'\n");
			return -DER_INVAL;
		}
		entry->dpe_type = DAOS_PROP_CO_REDUN_FAC;
	} else {
		fprintf(stderr, "supported prop names are label/cksum/cksum_size/srv_cksum/rf\n");
		return -DER_INVAL;
	}

	props->dpp_nr++;
	return 0;
}

/* format for list of properties is "<name>:<value>[,<name>:<value>,...]" */
static int
daos_parse_properties(char *props_string, daos_prop_t *props)
{
	char name[20], value[DAOS_PROP_LABEL_MAX_LEN] /* for label */;
	char *cur = props_string, *comma, *colon;
	size_t len = strlen(props_string);
	int rc = 0;

	while (len > 0) {
		colon = strchr(cur, ':');
		if (colon == NULL) {
			fprintf(stderr, "wrong format for properties\n");
			rc = -DER_INVAL;
			break;
		}
		*colon = '\0';
		if (strlen(cur) >= sizeof(name)) {
			fprintf(stderr, "too long prop name '%s'\n",
				cur);
			*colon = ':';
			rc = -DER_INVAL;
			break;
		}
		strcpy(name, cur);
		*colon = ':';
		comma = strchr(colon + 1, ',');
		if (comma == NULL) {
			if (strlen(colon + 1) < sizeof(value)) {
				strcpy(value, colon + 1);
				/* last property in list */
				/* break; */
				len -= strlen(cur);
			} else {
				fprintf(stderr, "too long prop value '%s'\n",
					colon + 1);
				rc = -DER_INVAL;
				break;
			}
		} else {
			*comma = '\0';
			if (sizeof(value) > strlen(colon + 1)) {
				strcpy(value, colon + 1);
				len = len - (comma - cur + 1);
				cur = comma + 1;
				*comma = ',';
				/* continue; */
			} else {
				fprintf(stderr, "too long prop value '%s'\n",
					colon + 1);
				*comma = ',';
				rc = -DER_INVAL;
				break;
			}
		}
		rc = daos_parse_property(name, value, props);
		if (rc)
			break;
	}

	return rc;
}

/* values to identify options with no small value in getopt_long() */
enum {
	DAOS_PROPERTIES_OPTION = 1,
};

static int
common_op_parse_hdlr(int argc, char *argv[], struct cmd_args_s *ap)
{
	/* Note: will rely on getopt_long() substring matching for shorter
	 * option variants. Specifically --sys= for --sys-name=
	 */
	struct option		options[] = {
		{"sys-name",	required_argument,	NULL,	'G'},
		{"pool",	required_argument,	NULL,	'p'},
		{"svc",		required_argument,	NULL,	'm'},
		{"cont",	required_argument,	NULL,	'c'},
		{"src-pool",	required_argument,	NULL,	'S'},
		{"dst-pool",	required_argument,	NULL,	'D'},
		{"src-cont",	required_argument,	NULL,	'C'},
		{"dst-cont",	required_argument,	NULL,	'T'},
		{"src-svc",	required_argument,	NULL,	'X'},
		{"dst-svc",	required_argument,	NULL,	'x'},
		{"attr",	required_argument,	NULL,	'a'},
		{"value",	required_argument,	NULL,	'v'},
		{"path",	required_argument,	NULL,	'd'},
		{"type",	required_argument,	NULL,	't'},
		{"oclass",	required_argument,	NULL,	'o'},
		{"chunk_size",	required_argument,	NULL,	'z'},
		{"snap",	required_argument,	NULL,	's'},
		{"epc",		required_argument,	NULL,	'e'},
		{"epcrange",	required_argument,	NULL,	'r'},
		{"oid",		required_argument,	NULL,	'i'},
		{"force",	no_argument,		NULL,	'f'},
		{"properties",	required_argument,	NULL,	DAOS_PROPERTIES_OPTION},
		{"outfile",	required_argument,	NULL,	'O'},
		{"verbose",	no_argument,		NULL,	'V'},
		{"acl-file",	required_argument,	NULL,	'A'},
		{"entry",	required_argument,	NULL,	'E'},
		{"user",	required_argument,	NULL,	'u'},
		{"group",	required_argument,	NULL,	'g'},
		{"principal",	required_argument,	NULL,	'P'},
		{NULL,		0,			NULL,	0}
	};
	int			rc;
	const int		RC_PRINT_HELP = 2;
	const int		RC_NO_HELP = -2;
	char			*cmdname = NULL;

	assert(ap != NULL);
	ap->p_op  = -1;
	ap->c_op  = -1;
	ap->cp_op = -1;
	ap->o_op  = -1;
	D_STRNDUP(ap->sysname, default_sysname, strlen(default_sysname));
	if (ap->sysname == NULL)
		return RC_NO_HELP;

	if ((strcmp(argv[1], "container") == 0) ||
	    (strcmp(argv[1], "cont") == 0)) {
		ap->c_op = cont_op_parse(argv[2]);
		if (ap->c_op == -1) {
			fprintf(stderr, "invalid container command: %s\n",
				argv[2]);
			return RC_PRINT_HELP;
		}
	} else if (strcmp(argv[1], "copy") == 0) {
		ap->cp_op = copy_op_parse(argv[2]);
		if (ap->cp_op == -1) {
			fprintf(stderr, "invalid copy command: %s\n",
				argv[2]);
			return RC_PRINT_HELP;
		}
	} else if (strcmp(argv[1], "pool") == 0) {
		ap->p_op = pool_op_parse(argv[2]);
		if (ap->p_op == -1) {
			fprintf(stderr, "invalid pool command: %s\n",
				argv[2]);
			return RC_PRINT_HELP;
		}
	} else if ((strcmp(argv[1], "object") == 0) ||
		   (strcmp(argv[1], "obj") == 0)) {
		ap->o_op = obj_op_parse(argv[2]);
		if (ap->o_op == -1) {
			fprintf(stderr, "invalid object command: %s\n",
				argv[2]);
			return RC_PRINT_HELP;
		}
	} else {
		/* main() may catch error. Keep this code just in case. */
		fprintf(stderr, "resource (%s): must be "
				 "pool, container or object\n", argv[1]);
		return RC_PRINT_HELP;
	}
	D_STRNDUP(cmdname, argv[2], strlen(argv[2]));
	if (cmdname == NULL)
		D_GOTO(out_free, rc = RC_NO_HELP);

	/* Parse command options. Use goto on any errors here
	 * since some options may result in resource allocation.
	 */
	while ((rc = getopt_long(argc, argv, "", options, NULL)) != -1) {
		switch (rc) {
		case 'G':
			D_FREE(ap->sysname);
			D_STRNDUP(ap->sysname, optarg, strlen(optarg));
			if (ap->sysname == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'p':
			if (uuid_parse(optarg, ap->p_uuid) != 0) {
				fprintf(stderr,
					"failed to parse pool UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'c':
			if (uuid_parse(optarg, ap->c_uuid) != 0) {
				fprintf(stderr,
					"failed to parse cont UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'S':
			if (uuid_parse(optarg, ap->src_p_uuid) != 0) {
				fprintf(stderr,
					"failed to parse src pool UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'D':
			if (uuid_parse(optarg, ap->dst_p_uuid) != 0) {
				fprintf(stderr,
					"failed to parse dst pool UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'C':
			if (uuid_parse(optarg, ap->src_cont_uuid) != 0) {
				fprintf(stderr,
					"failed to parse src cont UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'T':
			if (uuid_parse(optarg, ap->dst_cont_uuid) != 0) {
				fprintf(stderr,
					"failed to parse dst cont UUID: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'X':
			D_STRNDUP(ap->src_svc_str, optarg, strlen(optarg));
			if (ap->src_svc_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			ap->src_svc = daos_rank_list_parse(ap->src_svc_str, ",");
			break;
		case 'x':
			D_STRNDUP(ap->dst_svc_str, optarg, strlen(optarg));
			if (ap->dst_svc_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			ap->dst_svc = daos_rank_list_parse(ap->dst_svc_str, ",");
			break;
		case 'm':
			D_STRNDUP(ap->mdsrv_str, optarg, strlen(optarg));
			if (ap->mdsrv_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			ap->mdsrv = daos_rank_list_parse(ap->mdsrv_str, ",");
			break;

		case 'a':
			if (ap->attrname_str != NULL) {
				fprintf(stderr,
					"only one attribute name is allowed\n");
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			D_STRNDUP(ap->attrname_str, optarg, strlen(optarg));
			if (ap->attrname_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'v':
			if (ap->value_str != NULL) {
				fprintf(stderr,
					"only one attribute value is allowed\n");
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			D_STRNDUP(ap->value_str, optarg, strlen(optarg));
			if (ap->value_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'd':
			D_STRNDUP(ap->path, optarg, strlen(optarg));
			if (ap->path == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 't':
			daos_parse_ctype(optarg, &ap->type);
			if (ap->type == DAOS_PROP_CO_LAYOUT_UNKOWN) {
				fprintf(stderr, "unknown container type %s\n",
						optarg);
				D_GOTO(out_free, rc = RC_PRINT_HELP);
			}
			break;
		case 'o':
			ap->oclass = daos_oclass_name2id(optarg);
			if (ap->oclass == OC_UNKNOWN) {
				fprintf(stderr, "unknown object class: %s\n",
						optarg);
				D_GOTO(out_free, rc = RC_PRINT_HELP);
			}
			break;
		case 'z':
			ap->chunk_size = tobytes(optarg);
			if (ap->chunk_size == 0 ||
			    (ap->chunk_size == ULLONG_MAX && errno != 0)) {
				fprintf(stderr, "failed to parse chunk_size:"
					"%s\n", optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 's':
			D_STRNDUP(ap->snapname_str, optarg, strlen(optarg));
			if (ap->snapname_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'e':
			ap->epc = strtoull(optarg, NULL, 10);
			if (ap->epc == 0 ||
			    (ap->epc == ULLONG_MAX && errno != 0)) {
				fprintf(stderr, "failed to parse epc: %s\n",
					optarg);
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'r':
			D_STRNDUP(ap->epcrange_str, optarg, strlen(optarg));
			if (ap->epcrange_str == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			rc = epoch_range_parse(ap);
			if (rc != 0) {
				fprintf(stderr, "failed to parse epcrange\n");
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'i':
			rc = daos_obj_id_parse(optarg, &ap->oid);
			if (rc != 0) {
				fprintf(stderr, "oid format should be "
						"oid_hi.oid_lo\n");
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			break;
		case 'f':
			ap->force = 1;
			break;
		case 'O':
			D_STRNDUP(ap->outfile, optarg, strlen(optarg));
			if (ap->outfile == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'V':
			ap->verbose = true;
			break;
		case 'A':
			D_STRNDUP(ap->aclfile, optarg, strlen(optarg));
			if (ap->aclfile == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'E':
			D_STRNDUP(ap->entry, optarg, strlen(optarg));
			if (ap->entry == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'u':
			D_STRNDUP(ap->user, optarg, strlen(optarg));
			if (ap->user == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'g':
			D_STRNDUP(ap->group, optarg, strlen(optarg));
			if (ap->group == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case 'P':
			D_STRNDUP(ap->principal, optarg, strlen(optarg));
			if (ap->principal == NULL)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		case DAOS_PROPERTIES_OPTION:
			/* parse properties to be set at cont create time */
			/* alloc max */
			ap->props = daos_prop_alloc(DAOS_PROP_ENTRIES_MAX_NR);
			if (ap->props == NULL) {
				fprintf(stderr, "unable to allocate props struct and array\n");
				D_GOTO(out_free, rc = RC_NO_HELP);
			}
			/* fake number of entries in array to be used for
			 * current entry to be filled
			 */
			ap->props->dpp_nr = 0;
			rc = daos_parse_properties(optarg, ap->props);
			if (rc != 0)
				D_GOTO(out_free, rc = RC_NO_HELP);
			break;
		default:
			fprintf(stderr, "unknown option : %d\n", rc);
			D_GOTO(out_free, rc = RC_PRINT_HELP);
		}
	}

	cmd_args_print(ap);

	/* Check for any unimplemented commands, print help */
	if (ap->p_op != -1 &&
	    (ap->p_op == POOL_STAT)) {
		fprintf(stderr,
			"pool %s not yet implemented\n", cmdname);
		D_GOTO(out_free, rc = RC_NO_HELP);
	}

	if (ap->c_op != -1 &&
	    (ap->c_op == CONT_LIST_OBJS ||
	     ap->c_op == CONT_STAT ||
	     ap->c_op == CONT_DEL_ATTR ||
	     ap->c_op == CONT_ROLLBACK)) {
		fprintf(stderr,
			"container %s not yet implemented\n", cmdname);
		D_GOTO(out_free, rc = RC_NO_HELP);
	}

	if (ap->o_op != -1 &&
	    ((ap->o_op == OBJ_LIST_KEYS) ||
	     (ap->o_op == OBJ_DUMP))) {
		fprintf(stderr,
			"object %s not yet implemented\n", cmdname);
		D_GOTO(out_free, rc = RC_NO_HELP);
	}

        if (ap->cp_op != COPY_CONT) {
	    /* Verify pool svc provided */
	    ARGS_VERIFY_MDSRV(ap, out_free, rc = RC_PRINT_HELP);
        }

	D_FREE(cmdname);
	return 0;

out_free:
	d_rank_list_free(ap->mdsrv);
	d_rank_list_free(ap->src_svc);
	d_rank_list_free(ap->dst_svc);
	if (ap->sysname != NULL)
		D_FREE(ap->sysname);
	if (ap->mdsrv_str != NULL)
		D_FREE(ap->mdsrv_str);
	if (ap->src_svc_str != NULL)
		D_FREE(ap->src_svc_str);
	if (ap->dst_svc_str != NULL)
		D_FREE(ap->dst_svc_str);
	if (ap->attrname_str != NULL)
		D_FREE(ap->attrname_str);
	if (ap->value_str != NULL)
		D_FREE(ap->value_str);
	if (ap->path != NULL)
		D_FREE(ap->path);
	if (ap->snapname_str != NULL)
		D_FREE(ap->snapname_str);
	if (ap->epcrange_str != NULL)
		D_FREE(ap->epcrange_str);
	if (ap->props) {
		/* restore number of entries in array for freeing */
		ap->props->dpp_nr = DAOS_PROP_ENTRIES_MAX_NR;
		daos_prop_free(ap->props);
	}
	if (ap->outfile != NULL)
		D_FREE(ap->outfile);
	if (ap->aclfile != NULL)
		D_FREE(ap->aclfile);
	if (ap->entry != NULL)
		D_FREE(ap->entry);
	if (ap->principal != NULL)
		D_FREE(ap->principal);
	D_FREE(cmdname);
	return rc;
}

/* For operations that take <pool_uuid, pool_sysname, pool_svc_ranks>
 * invoke op-specific handler function.
 */
static int
pool_op_hdlr(struct cmd_args_s *ap)
{
	int			rc = 0;
	enum pool_op		op;
	const int		RC_PRINT_HELP = 2;

	assert(ap != NULL);
	op = ap->p_op;

	ARGS_VERIFY_PUUID(ap, out, rc = RC_PRINT_HELP);

	switch (op) {
	case POOL_QUERY:
		rc = pool_query_hdlr(ap);
		break;
	case POOL_LIST_CONTAINERS:
		rc = pool_list_containers_hdlr(ap);
		break;

	/* TODO: implement when statistics available */
	case POOL_STAT:
		/* rc = pool_stat_hdlr(ap); */
		break;
	case POOL_GET_PROP:
		rc = pool_get_prop_hdlr(ap);
		break;
	case POOL_GET_ATTR:
		rc = pool_get_attr_hdlr(ap);
		break;
	case POOL_SET_ATTR:
		rc = pool_set_attr_hdlr(ap);
		break;
	case POOL_LIST_ATTRS:
		rc = pool_list_attrs_hdlr(ap);
		break;
	default:
		break;
	}

out:
	return rc;
}

static int
cont_op_hdlr(struct cmd_args_s *ap)
{
	daos_cont_info_t	cont_info;
	int			rc;
	int			rc2;
	enum cont_op		op;
	const int		RC_PRINT_HELP = 2;

	assert(ap != NULL);
	op = ap->c_op;

	/* All container operations require a pool handle, connect here.
	 * Take specified pool UUID or look up through unified namespace.
	 */
	if ((op != CONT_CREATE) && (ap->path != NULL)) {
		struct duns_attr_t dattr = {0};

		ARGS_VERIFY_PATH_NON_CREATE(ap, out, rc = RC_PRINT_HELP);

		/* Resolve pool, container UUIDs from path if needed */
		rc = duns_resolve_path(ap->path, &dattr);
		if (rc) {
			fprintf(stderr, "could not resolve pool, container "
					"by path: %s\n", ap->path);
			D_GOTO(out, rc);
		}
		ap->type = dattr.da_type;
		uuid_copy(ap->p_uuid, dattr.da_puuid);
		uuid_copy(ap->c_uuid, dattr.da_cuuid);
	} else {
		ARGS_VERIFY_PUUID(ap, out, rc = RC_PRINT_HELP);
	}

	rc = daos_pool_connect(ap->p_uuid, ap->sysname, ap->mdsrv,
			       DAOS_PC_RW, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	/* container UUID: user-provided, generated here or by uns library */

	/* for container lookup ops: if no path specified, require --cont */
	if ((op != CONT_CREATE) && (ap->path == NULL))
		ARGS_VERIFY_CUUID(ap, out, rc = RC_PRINT_HELP);

	/* container create scenarios (generate UUID if necessary):
	 * 1) both --cont, --path : uns library will use specified c_uuid.
	 * 2) --cont only         : use specified c_uuid.
	 * 3) --path only         : uns library will create & return c_uuid
	 *                          (currently c_uuid null / clear).
	 * 4) neither specified   : create a UUID in c_uuid.
	 */
	if ((op == CONT_CREATE) && (ap->path == NULL) &&
	    (uuid_is_null(ap->c_uuid)))
		uuid_generate(ap->c_uuid);

	if (op != CONT_CREATE && op != CONT_DESTROY) {
		rc = daos_cont_open(ap->pool, ap->c_uuid, DAOS_COO_RW,
				    &ap->cont, &cont_info, NULL);
		if (rc != 0) {
			fprintf(stderr, "cont open failed: %d\n", rc);
			D_GOTO(out_disconnect, rc);
		}
	}

	switch (op) {
	case CONT_CREATE:
		if (ap->path != NULL)
			rc = cont_create_uns_hdlr(ap);
		else
			rc = cont_create_hdlr(ap);
		break;
	case CONT_DESTROY:
		rc = cont_destroy_hdlr(ap);
		break;

	/* TODO: implement the following ops */
	case CONT_LIST_OBJS:
		/* rc = cont_list_objs_hdlr(ap); */
		break;
	case CONT_QUERY:
		rc = cont_query_hdlr(ap);
		break;
	case CONT_STAT:
		/* rc = cont_stat_hdlr(ap); */
		break;
	case CONT_GET_PROP:
		rc = cont_get_prop_hdlr(ap);
		break;
	case CONT_SET_PROP:
		rc = cont_set_prop_hdlr(ap);
		break;
	case CONT_LIST_ATTRS:
		rc = cont_list_attrs_hdlr(ap);
		break;
	case CONT_DEL_ATTR:
		/* rc = cont_del_attr_hdlr(ap); */
		break;
	case CONT_GET_ATTR:
		rc = cont_get_attr_hdlr(ap);
		break;
	case CONT_SET_ATTR:
		rc = cont_set_attr_hdlr(ap);
		break;
	case CONT_CREATE_SNAP:
		rc = cont_create_snap_hdlr(ap);
		break;
	case CONT_LIST_SNAPS:
		rc = cont_list_snaps_hdlr(ap);
		break;
	case CONT_DESTROY_SNAP:
		rc = cont_destroy_snap_hdlr(ap);
		break;
	case CONT_ROLLBACK:
		/* rc = cont_rollback_hdlr(ap); */
		break;
	case CONT_GET_ACL:
		rc = cont_get_acl_hdlr(ap);
		break;
	case CONT_OVERWRITE_ACL:
		rc = cont_overwrite_acl_hdlr(ap);
		break;
	case CONT_UPDATE_ACL:
		rc = cont_update_acl_hdlr(ap);
		break;
	case CONT_DELETE_ACL:
		rc = cont_delete_acl_hdlr(ap);
		break;
	case CONT_SET_OWNER:
		rc = cont_set_owner_hdlr(ap);
		break;
	default:
		break;
	}

	/* Container close in normal and error flows: preserve rc */
	if (op != CONT_CREATE && op != CONT_DESTROY) {
		rc2 = daos_cont_close(ap->cont, NULL);
		if (rc2 != 0)
			fprintf(stderr, "Container close failed: %d\n", rc2);
		if (rc == 0)
			rc = rc2;
	}

out_disconnect:
	/* Pool disconnect in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);
	if (rc == 0)
		rc = rc2;

out:
	return rc;
}

#define ENUM_KEY_BUF		32 /* size of each dkey/akey */
#define ENUM_LARGE_KEY_BUF	(512 * 1024) /* 512k large key */
#define ENUM_DESC_NR		5 /* number of keys/records returned by enum */
#define ENUM_DESC_BUF		512 /* all keys/records returned by enum */
static int
copy_op_hdlr(struct cmd_args_s *ap)
{
	int			rc;
	daos_cont_info_t	src_cont_info;
	daos_cont_info_t	dst_cont_info;
	enum copy_op		op;

	assert(ap != NULL);
	op = ap->cp_op;
	rc = 0;

	switch (op) {
	case COPY_CONT:
                {
	        //printf("\tsrc pool UUID: "DF_UUIDF"\n", DP_UUID(ap->src_p_uuid));
	        //printf("\tsrc cont UUID: "DF_UUIDF"\n", DP_UUID(ap->src_cont_uuid));
	        //printf("\tdst pool UUID: "DF_UUIDF"\n", DP_UUID(ap->dst_p_uuid));
	        //printf("\tdst cont UUID: "DF_UUIDF"\n", DP_UUID(ap->dst_cont_uuid));
	        //printf("\tsrc svc: "DF_UUIDF"\n", DP_UUID(ap->src_svc));
	        //printf("\tdst svc: "DF_UUIDF"\n", DP_UUID(ap->dst_svc));

		/* connect to source pool */
	        rc = daos_pool_connect(ap->src_p_uuid, ap->sysname, ap->src_svc,
			               DAOS_PC_RW, &ap->pool,
			               NULL /* info */, NULL /* ev */);
	        if (rc != 0) {
		        fprintf(stderr, "failed to connect to pool: %d\n", rc);
	        }
                
                /* open source container */
	        rc = daos_cont_open(ap->pool, ap->src_cont_uuid, DAOS_COO_RW,
			            &ap->cont, &src_cont_info, NULL);
	        if (rc != 0) {
		        fprintf(stderr, "src cont open failed: %d\n", rc);
		        D_GOTO(out_disconnect, rc);
	        }

		/* if given source and destination pools are different, then connect
 		 * to the destination pool */
		if (uuid_compare(ap->src_p_uuid, ap->dst_p_uuid) != 0) {
	        	rc = daos_pool_connect(ap->dst_p_uuid, ap->sysname, ap->dst_svc,
				               DAOS_PC_RW, &ap->dst_pool,
			       		       NULL /* info */, NULL /* ev */);
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
				/* query layout type of source container, if dst container needs to be
		 		 * created it uses the same layout type as the source */
				daos_prop_t		*prop_query;
				struct daos_prop_entry	*entry;
				char			type[10] = {};
				uint32_t		i;
				uint32_t		entry_type;

	    			if (uuid_is_null(ap->dst_cont_uuid)) 
					uuid_generate(ap->dst_cont_uuid);

				prop_query = daos_prop_alloc(DAOS_PROP_CO_NUM);
				if (prop_query == NULL)
					return -DER_NOMEM;
				entry_type = DAOS_PROP_CO_MIN + 1;
				for (i = 0; i < prop_query->dpp_nr; entry_type++) {
					prop_query->dpp_entries[i].dpe_type = entry_type;
					i++;
				}
				rc = daos_cont_query(ap->cont, NULL, prop_query, NULL);
				if (rc) {
					fprintf(stderr, "Container query failed, result: %d\n", rc);
				}
				entry = daos_prop_entry_get(prop_query, DAOS_PROP_CO_LAYOUT_TYPE);
				if (entry == NULL) {
					fprintf(stderr, "layout type property not found\n");
				}
				daos_unparse_ctype(entry->dpe_val, type);
				D_PRINT("layout type -> "DF_U64"/%s\n", entry->dpe_val, type);

				/* if cont open failed, try to create one */
				/* create the dst container */
				/** allow creating a POSIX container without a link in the UNS path */
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
				if (rc != 0) {
					fprintf(stderr, "failed to create destination container: %d\n", rc);
				}
				/* print out created cont uuid */
				fprintf(stdout, "Successfully created container "DF_UUIDF"\n", DP_UUID(ap->dst_cont_uuid));
	        		rc = daos_cont_open(ap->pool, ap->dst_cont_uuid, DAOS_COO_RW,
					&ap->dst_cont, &dst_cont_info, NULL);
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
 			D_ASSERTF(rc == 0, "%d\n", rc);
 			//D_PRINT("returned %d oids\n", oids_nr);
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

                                /* loop to enumerate dkeys */
                                daos_anchor_t dkey_anchor = {0}; 
				while (!daos_anchor_is_eof(&dkey_anchor)) {
                         		char            dkey_enum_buf[ENUM_DESC_BUF] = {0};
				        uint32_t        number                       = ENUM_DESC_NR;
                                        char            dkey[ENUM_KEY_BUF]           = {0};
	                                daos_key_desc_t dkey_kds[ENUM_DESC_NR]       = {0};
                         		d_sg_list_t     dkey_sgl;
                         		d_iov_t         dkey_iov;

                                	dkey_sgl.sg_nr     = 1;
	                        	dkey_sgl.sg_nr_out = 0;
	                        	dkey_sgl.sg_iovs   = &dkey_iov;

	                        	d_iov_set(&dkey_iov, dkey_enum_buf, ENUM_DESC_BUF);
                                        memset(dkey_enum_buf, 0, sizeof(dkey_enum_buf));

					/* get dkeys */
					rc = daos_obj_list_dkey(oh, DAOS_TX_NONE, &number, dkey_kds,
						&dkey_sgl, &dkey_anchor, NULL);
					if (rc)
						return daos_der2errno(rc);       

					/* if no dkeys were returned move on */
					if (number == 0)
						continue;
                                        char* ptr;
					int   rc;
                                        int   j;
					/* parse out individual dkeys based on key length and numver of dkeys returned */
                			for (ptr = dkey_enum_buf, j = 0; j < number; j++) {
                               			/* Print enumerated dkeys */
            					daos_key_t diov;
                               			snprintf(dkey, dkey_kds[j].kd_key_len + 1, "%s", ptr);
	                        		d_iov_set(&diov, (void*)dkey, dkey_kds[j].kd_key_len);
	                             		//printf("j:%d dkey iov buf:%s len:%d\n", j, (char*)diov.iov_buf, (int)dkey_kds[j].kd_key_len);
		                       	        ptr += dkey_kds[j].kd_key_len;
						/* loop to enumerate akeys */
                                		daos_anchor_t akey_anchor = {0}; 
						while (!daos_anchor_is_eof(&akey_anchor)) {
	               		       		   	char            akey_enum_buf[ENUM_DESC_BUF] = {0};
						        uint32_t        number                       = ENUM_DESC_NR;
               		                        	char            akey[ENUM_KEY_BUF]           = {0};
		               		                daos_key_desc_t akey_kds[ENUM_DESC_NR]       = {0};
       	                		  		d_sg_list_t     akey_sgl;
		                         		d_iov_t         akey_iov;

			                               	akey_sgl.sg_nr     = 1;
				                        akey_sgl.sg_nr_out = 0;
		               		         	akey_sgl.sg_iovs   = &akey_iov;

		       		                 	d_iov_set(&akey_iov, akey_enum_buf, ENUM_DESC_BUF);
       	                        		        memset(akey_enum_buf, 0, sizeof(akey_enum_buf));

							/* get akeys */
							rc = daos_obj_list_akey(oh, DAOS_TX_NONE, &diov, &number, akey_kds,
								&akey_sgl, &akey_anchor,
							NULL);
							if (rc)
								return daos_der2errno(rc);       

							/* if no akeys returned move on */
							if (number == 0)
								continue;
       	                                		char* ptr;
							//int   rc;
       	        		                        int   j;
							/* parse out individual akeys based on key length and numver of dkeys returned */
                					for (ptr = akey_enum_buf, j = 0; j < number; j++) {
                                                                daos_key_t aiov;
								daos_iod_t iod;
                                                                snprintf(akey, akey_kds[j].kd_key_len + 1, "%s", ptr);
                                                                d_iov_set(&aiov, (void*)akey, akey_kds[j].kd_key_len);
                                                                //printf("\tj:%d akey:%s len:%d\n", j, (char*)aiov.iov_buf, (int)akey_kds[j].kd_key_len);

								/* set iod values */
								iod.iod_nr   = 1;
								iod.iod_type = DAOS_IOD_SINGLE;
								iod.iod_size = DAOS_REC_ANY;

								d_iov_set(&iod.iod_name, (void*)akey, strlen(akey));
                                                                /* I meant with the probe that you do a fetch (with NULL sgl)
                                                                 * of single value type, and if that returns iod_size == 0, then
                                                                 * a single value does not exist.*/
								/* do fetch with sgl == NULL to check if iod type (ARRAY OR SINGLE VAL) */
                                                                rc = daos_obj_fetch(oh, DAOS_TX_NONE, 0, &diov, 1, &iod, NULL, NULL, NULL);
								//printf("\tRC PROBE FETCH: %d, IOD SIZE: %d\n", rc, (int)iod.iod_size);

								/* if iod_size == 0 then this is a DAOS_IOD_ARRAY type */
								if ((int)iod.iod_size == 0) {
									/* enumerate all recxs since this is array type */
                                					daos_anchor_t recx_anchor = {0}; 
									int i;
									while (!daos_anchor_is_eof(&recx_anchor)) {

										daos_epoch_range_t	eprs[5];
										daos_recx_t		recxs[5];
										daos_size_t		size;

										/* list all recx for this dkey/akey */
										uint32_t number = 5;
										rc = daos_obj_list_recx(oh, DAOS_TX_NONE, &diov,
											&aiov, &size, &number, recxs, eprs, &recx_anchor,
											true, NULL);

										/* if no recx is returned for this dkey/akey move on */
										if (number == 0) 
											continue;
										for (i = 0; i < number; i++) {
											uint64_t    abuf_len = recxs[i].rx_nr;
										        char        abuf[abuf_len];
											d_sg_list_t a_sgl;
											d_iov_t     a_iov;
											daos_iod_t  a_iod;

											/* set iod values */
											a_iod.iod_type  = DAOS_IOD_ARRAY;
											a_iod.iod_size  = 1;
											a_iod.iod_nr    = 1;
											a_iod.iod_recxs = &recxs[i];

											/* set sgl values */
											a_sgl.sg_nr     = 1;
											a_sgl.sg_nr_out = 0;
											a_sgl.sg_iovs   = &a_iov;

											d_iov_set(&a_iod.iod_name, (void*)akey, strlen(akey));
											d_iov_set(&a_iov, abuf, abuf_len);	
											//printf("\ti: %d iod_size: %d rx_nr:%d, rx_idx:%d\n",
											//	i, (int)size, (int)recxs[i].rx_nr, (int)recxs[i].rx_idx);
											/* fetch recx values from source */
                                                                			rc = daos_obj_fetch(oh, DAOS_TX_NONE, 0, &diov, 1, &a_iod,
												&a_sgl, NULL, NULL);
											//printf("\tRC ARRAY VAL FETCH: %d, SGL DATA LEN: %d\n", rc,
											//	(int)a_sgl.sg_iovs[0].iov_len);
											/* update fetched recx values and place in destination object */
                                                                			rc = daos_obj_update(dst_oh, DAOS_TX_NONE, 0, &diov, 1, &a_iod,
												&a_sgl, NULL);
											//printf("\tRC ARRAY VAL UPDATE: %d, SGL DATA LEN: %d\n", rc,
											//	(int)a_sgl.sg_iovs[0].iov_len);
										}
									}
									
								} else {
									/* if iod_type is single value just fetch iod size from source
 									 * and update in destination object */
								        int         sbuf_len = (int)iod.iod_size;
									char        sbuf[sbuf_len];
									d_sg_list_t s_sgl;
									d_iov_t     s_iov;

									/* set sgl values */
									s_sgl.sg_nr     = 1;
									s_sgl.sg_nr_out = 0;
									s_sgl.sg_iovs   = &s_iov;
									d_iov_set(&s_iov, sbuf, sbuf_len);
                                                                	rc = daos_obj_fetch(oh, DAOS_TX_NONE, 0, &diov, 1, &iod, &s_sgl, NULL, NULL);
									//printf("\tRC SINGLE VAL FETCH: %d, IOD SIZE: %d\n", rc, (int)iod.iod_size);
                                                                	rc = daos_obj_update(dst_oh, DAOS_TX_NONE, 0, &diov, 1, &iod, &s_sgl, NULL);
									//printf("\tRC SINGLE VAL UPDATE: %d, IOD SIZE: %d\n", rc, (int)iod.iod_size);
								}
								/* advance to next akey returned */	
                                                                ptr += akey_kds[j].kd_key_len;
               			 			}
						}
					}
 				}
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
 		D_ASSERT(rc == 0);
                }
                break;
	default:
		break;
	}

	/* Container close in normal and error flows: preserve rc */
	rc = daos_cont_close(ap->cont, NULL);
	if (rc != 0)
		fprintf(stderr, "src container close failed: %d\n", rc);

        /* close dst container */
	rc = daos_cont_close(ap->dst_cont, NULL);
	if (rc != 0)
		fprintf(stderr, "dst container close failed: %d\n", rc);

out_disconnect:
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
//out:
	return rc;
}

/* For operations that take <oid>
 * invoke op-specific handler function.
 */
static int
obj_op_hdlr(struct cmd_args_s *ap)
{
	daos_cont_info_t	cont_info;
	int			rc;
	int			rc2;
	enum obj_op		op;
	const int		RC_PRINT_HELP = 2;

	assert(ap != NULL);
	op = ap->o_op;

	rc = 0;
	ARGS_VERIFY_PUUID(ap, out, rc = RC_PRINT_HELP);
	ARGS_VERIFY_CUUID(ap, out, rc = RC_PRINT_HELP);
	ARGS_VERIFY_OID(ap, out, rc = RC_PRINT_HELP);

	/* TODO: support container lookup by path? */

	rc = daos_pool_connect(ap->p_uuid, ap->sysname, ap->mdsrv,
			       DAOS_PC_RW, &ap->pool,
			       NULL /* info */, NULL /* ev */);
	if (rc != 0) {
		fprintf(stderr, "failed to connect to pool: %d\n", rc);
		D_GOTO(out, rc);
	}

	rc = daos_cont_open(ap->pool, ap->c_uuid, DAOS_COO_RW,
			&ap->cont, &cont_info, NULL);
	if (rc != 0) {
		fprintf(stderr, "cont open failed: %d\n", rc);
		D_GOTO(out_disconnect, rc);
	}

	switch (op) {
	case OBJ_QUERY:
		rc = obj_query_hdlr(ap);
		break;
	case OBJ_DUMP:
		break;
	default:
		break;
	}

	/* Container close in normal and error flows: preserve rc */
	rc2 = daos_cont_close(ap->cont, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Container close failed: %d\n", rc2);
	if (rc == 0)
		rc = rc2;

out_disconnect:
	/* Pool disconnect in normal and error flows: preserve rc */
	rc2 = daos_pool_disconnect(ap->pool, NULL);
	if (rc2 != 0)
		fprintf(stderr, "Pool disconnect failed : %d\n", rc2);
	if (rc == 0)
		rc = rc2;

out:
	return rc;
}

#define OCLASS_NAMES_LIST_SIZE 512

static void
print_oclass_names_list(FILE *stream)
{
	char *str;
	size_t size = OCLASS_NAMES_LIST_SIZE, len;

again:
	str = malloc(size);
	if (str == NULL) {
		fprintf(stderr, "failed to malloc %zu bytes to gather oclass names list\n",
			size);
		return;
	}
	len = daos_oclass_names_list(size, str);
	if (len <= 0)
		goto out;
	if (len < size)
		fprintf(stream, "%s", str);
	else {
		size = len + 1;
		free(str);
		goto again;
	}
out:
	free(str);
}

#define FIRST_LEVEL_HELP() \
do { \
	fprintf(stream, \
	"usage: daos RESOURCE COMMAND [OPTIONS]\n" \
	"resources:\n" \
	"	  pool             pool\n" \
	"	  container (cont) container\n" \
	"	  object (obj)     object\n" \
	"	  version          print command version\n" \
	"	  help             print this message and exit\n"); \
	fprintf(stream, "\n"); \
	fprintf(stream, "use 'daos help RESOURCE' for resource specifics\n"); \
} while (0)

#define ALL_CONT_CMDS_HELP() \
do { \
	fprintf(stream, "\n" \
	"container (cont) commands:\n" \
	"	  create           create a container\n" \
	"	  destroy          destroy a container\n" \
	"	  list-objects     list all objects in container\n" \
	"	  list-obj\n" \
	"	  query            query a container\n" \
	"	  get-prop         get all container's properties\n" \
	"	  set-prop         set container's properties\n" \
	"	  get-acl          get a container's ACL\n" \
	"	  overwrite-acl    replace a container's ACL\n" \
	"	  update-acl       add/modify entries in a container's ACL\n" \
	"	  delete-acl       delete an entry from a container's ACL\n" \
	"	  set-owner        change the user and/or group that own a container\n" \
	"	  stat             get container statistics\n" \
	"	  list-attrs       list container user-defined attributes\n" \
	"	  del-attr         delete container user-defined attribute\n" \
	"	  get-attr         get container user-defined attribute\n" \
	"	  set-attr         set container user-defined attribute\n" \
	"	  create-snap      create container snapshot (optional name)\n" \
	"			   at most recent committed epoch\n" \
	"	  list-snaps       list container snapshots taken\n" \
	"	  destroy-snap     destroy container snapshots\n" \
	"			   by name, epoch or range\n" \
	"	  rollback         roll back container to specified snapshot\n"); \
	fprintf(stream, "\n"); \
	fprintf(stream, "use 'daos help cont|container COMMAND' for command specific options\n"); \
} while (0)

#define ALL_BUT_CONT_CREATE_OPTS_HELP() \
do { \
	fprintf(stream, \
	"container options (query, and all commands except create):\n" \
	"	  <pool options>   with --cont use: (--pool, --sys-name, --svc)\n" \
	"	  <pool options>   with --path use: (--sys-name, --svc)\n" \
	"	--cont=UUID        (mandatory, or use --path)\n" \
	"	--path=PATHSTR     (mandatory, or use --cont)\n"); \
} while (0)

static int
help_hdlr(int argc, char *argv[], struct cmd_args_s *ap)
{
	FILE *stream;

	assert(ap != NULL);

	stream = (ap->ostream != NULL) ? ap->ostream : stdout;

	fprintf(stream, "daos command (v%s)\n", DAOS_VERSION);

	//if (argc <= 2 && (strcmp(argv[2], "copy") != 0)) {
	//	FIRST_LEVEL_HELP();
	//} else
        if (strcmp(argv[2], "pool") == 0) {
		fprintf(stream, "\n"
		"pool commands:\n"
		"	  list-containers  list all containers in pool\n"
		"	  list-cont\n"
		"	  query            query a pool\n"
		"	  stat             get pool statistics\n"
		"	  list-attrs       list pool user-defined attributes\n"
		"	  get-attr         get pool user-defined attribute\n");

		fprintf(stream,
		"pool options:\n"
		"	--pool=UUID        pool UUID\n"
		"	--sys-name=STR     DAOS system name context for servers (\"%s\")\n"
		"	--sys=STR\n"
		"	--svc=RANKS        pool service replicas like 1,2,3\n"
		"	--attr=NAME        pool attribute name to get\n",
			default_sysname);

	} else if (strcmp(argv[2], "copy") == 0) {
		fprintf(stream, "\n"
		"copy commands:\n"
		"	  copy             copy a cont\n");

		fprintf(stream,
		"copy options:\n"
		"	--src_pool=UUID    src pool UUID\n"
		"	--dst_pool=UUID    dst pool UUID\n"
		"	--src_cont=UUID    src cont UUID\n"
		"	--dst_cont=UUID    dst cont UUID\n");

	} else if (strcmp(argv[2], "container") == 0 ||
		   strcmp(argv[2], "cont") == 0) {
		if (argc == 3) {
			ALL_CONT_CMDS_HELP();
		} else if (strcmp(argv[3], "create") == 0) {
			fprintf(stream,
			"container options (create by UUID):\n"
			"	  <pool options>   (--pool, --sys-name, --svc)\n"
			"	--cont=UUID        (optional) container UUID (or generated)\n"
			"container options (create and link to namespace path):\n"
			"	  <pool/cont opts> (--pool, --sys-name, --svc, --cont [optional])\n"
			"	--path=PATHSTR     container namespace path\n"
			"container create common optional options:\n"
			"	--type=CTYPESTR    container type (HDF5, POSIX)\n"
			"	--oclass=OCLSSTR   container object class\n"
			"			   (");
			/* vs hardcoded list like "tiny, small, large, R2, R2S, repl_max" */
			print_oclass_names_list(stream);
			fprintf(stream, ")\n"
			"	--chunk_size=BYTES chunk size of files created. Supports suffixes:\n"
			"			   K (KB), M (MB), G (GB), T (TB), P (PB), E (EB)\n"
			"	--properties=<name>:<value>[,<name>:<value>,...]\n"
			"			   supported prop names are label, cksum,\n"
			"				cksum_size, srv_cksum, rf\n"
			"			   label value can be any string\n"
			"			   cksum supported values are off, crc[16,32,64], sha1\n"
			"			   cksum_size can be any size\n"
			"			   srv_cksum values can be on, off\n"
			"			   rf supported values are [0-4]\n"
			"	--acl-file=PATH    input file containing ACL\n"
			"	--user=ID          user who will own the container.\n"
			"			   format: username@[domain]\n"
			"			   default is the effective user\n"
			"	--group=ID         group who will own the container.\n"
			"			   format: groupname@[domain]\n"
			"			   default is the effective group\n");
		} else if (strcmp(argv[3], "destroy") == 0) {
			fprintf(stream,
			"container options (destroy):\n"
			"	--force            destroy container regardless of state\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "get-attr") == 0 ||
			   strcmp(argv[3], "set-attr") == 0 ||
			   strcmp(argv[3], "del-attr") == 0) {
			fprintf(stream,
			"container options (attribute-related):\n"
			"	--attr=NAME        container attribute name to set, get, del\n"
			"	--value=VALUESTR   container attribute value to set\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "create-snap") == 0 ||
			   strcmp(argv[3], "destroy-snap") == 0 ||
			   strcmp(argv[3], "rollback") == 0) {
			fprintf(stream,
			"container options (snapshot and rollback-related):\n"
			"	--snap=NAME        container snapshot (create/destroy-snap, rollback)\n"
			"	--epc=EPOCHNUM     container epoch (destroy-snap, rollback)\n"
			"	--eprange=B-E      container epoch range (destroy-snap)\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "set-prop") == 0) {
			fprintf(stream,
			"container options (set-prop):\n"
			"	--properties=<name>:<value>[,<name>:<value>,...]\n"
			"			   supported prop names: label\n"
			"			   label value can be any string\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "get-acl") == 0 ||
			   strcmp(argv[3], "overwrite-acl") == 0 ||
			   strcmp(argv[3], "update-acl") == 0 ||
			   strcmp(argv[3], "delete-acl") == 0) {
			fprintf(stream,
			"container options (ACL-related):\n"
			"	--acl-file=PATH    input file containing ACL (overwrite-acl, "
			"			   update-acl)\n"
			"	--entry=ACE        add or modify a single ACL entry (update-acl)\n"
			"	--principal=ID     principal of entry (delete-acl)\n"
			"			   for users: u:name@[domain]\n"
			"			   for groups: g:name@[domain]\n"
			"			   special principals: OWNER@, GROUP@, EVERYONE@\n"
			"	--verbose          verbose mode (get-acl)\n"
			"	--outfile=PATH     write ACL to file (get-acl)\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "set-owner") == 0) {
			fprintf(stream,
			"container options (set-owner):\n"
			"	--user=ID          user who will own the container.\n"
			"			   format: username@[domain]\n"
			"	--group=ID         group who will own the container.\n"
			"			   format: groupname@[domain]\n");
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else if (strcmp(argv[3], "list-objects") == 0 ||
			   strcmp(argv[3], "list-obj") == 0 ||
			   strcmp(argv[3], "query") == 0 ||
			   strcmp(argv[3], "get-prop") == 0 ||
			   strcmp(argv[3], "stat") == 0 ||
			   strcmp(argv[3], "list-attrs") == 0 ||
			   strcmp(argv[3], "list-snaps") == 0) {
			ALL_BUT_CONT_CREATE_OPTS_HELP();
		} else {
			ALL_CONT_CMDS_HELP();
		}
	} else if (strcmp(argv[2], "obj") == 0 ||
		   strcmp(argv[2], "object") == 0) {
		fprintf(stream, "\n"
		"object (obj) commands:\n"
		"	  query            query an object's layout\n"
		"	  list-keys        list an object's keys\n"
		"	  dump             dump an object's contents\n");

		fprintf(stream,
		"object (obj) options:\n"
		"	  <pool options>   (--pool, --sys-name, --svc)\n"
		"	  <cont options>   (--cont)\n"
		"	--oid=HI.LO        object ID\n");

	} else {
		FIRST_LEVEL_HELP();
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int			rc = 0;
	command_hdlr_t		hdlr = NULL;
	struct cmd_args_s	dargs = {0};

	/* argv[1] is RESOURCE or "help" or "version";
	 * argv[2] if provided is a resource-specific command
	 */
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		fprintf(stdout, "daos version %s\n", DAOS_VERSION);
		return 0;
	} else if (argc < 2 || strcmp(argv[1], "help") == 0) {
		dargs.ostream = stdout;
		help_hdlr(argc, argv, &dargs);
		return 0;
	} else if (argc <= 2) {
		dargs.ostream = stdout;
		help_hdlr(argc, argv, &dargs);
		return 2;
	} else if ((strcmp(argv[1], "container") == 0) ||
		 (strcmp(argv[1], "cont") == 0)) {
		hdlr = cont_op_hdlr;
	} else if ((strcmp(argv[1], "copy") == 0)) {
		dargs.ostream = stdout;
		hdlr = copy_op_hdlr;
	} else if (strcmp(argv[1], "pool") == 0) {
		hdlr = pool_op_hdlr;
	} else if ((strcmp(argv[1], "object") == 0) ||
		 (strcmp(argv[1], "obj") == 0)) {
		hdlr = obj_op_hdlr;
        }

	if (hdlr == NULL) {
		dargs.ostream = stderr;
		help_hdlr(argc, argv, &dargs);
		return 2;
	}

	rc = daos_init();
	if (rc != 0) {
		fprintf(stderr, "failed to initialize daos: %d\n", rc);
		return 1;
	}

	/* Parse resource sub-command, and any options into dargs struct */
	rc = common_op_parse_hdlr(argc, argv, &dargs);
	if (rc != 0) {
		fprintf(stderr, "error parsing command line arguments\n");
		if (rc > 0) {
			dargs.ostream = stderr;
			help_hdlr(argc, argv, &dargs);
		}
		daos_fini();
		return -1;
	}

	/* Call resource-specific handler function */
	rc = hdlr(&dargs);

	/* Clean up dargs.mdsrv allocated in common_op_parse_hdlr() */
	d_rank_list_free(dargs.src_svc);
	d_rank_list_free(dargs.dst_svc);
	d_rank_list_free(dargs.mdsrv);

	D_FREE(dargs.mdsrv_str);
	D_FREE(dargs.src_svc_str);
	D_FREE(dargs.dst_svc_str);
	D_FREE(dargs.sysname);
	D_FREE(dargs.path);

	daos_fini();

	if (rc < 0)
		return 1;
	else if (rc > 0) {
		printf("rc: %d\n", rc);
		dargs.ostream = stderr;
		help_hdlr(argc, argv, &dargs);
		return 2;
	}

	return 0;
}
