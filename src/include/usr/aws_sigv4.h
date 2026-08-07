#ifndef _USR_AWS_SIGV4_H
#define _USR_AWS_SIGV4_H

/** @file
 *
 * AWS Signature Version 4 Calculation
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uri.h>

/** Elements of an AWS API request signature
 *
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-elements.html
 */
struct aws_sigv4_params {
	const char *payload;
	const char *service;
	const char *operation;
	const char *region;
	const char *amz_date;
	const char *date_stamp;
	const char *access_key;
	const char *secret_key;
	const char *session_token;
};

/** A JSON key-value pair */
struct json_kv {
	char *key;
	char *value;
};

extern int generate_get_secret_value_payload ( const char *secret_id, char **payload );
extern int aws_sigv4 ( const struct aws_sigv4_params *params, char **sigv4 );
extern int generate_aws_request ( const struct aws_sigv4_params *params, char *sigv4, char *payload, struct uri **uri );
extern int parse_and_store_credential ( char *response, struct json_kv *kv, char *json_key,
										struct named_setting *setting, char *setting_name );

#endif /* _USR_AWS_SIGV4_H */
