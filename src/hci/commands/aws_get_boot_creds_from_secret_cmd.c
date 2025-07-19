FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/params.h>
#include <ipxe/parseopt.h>
#include <ipxe/settings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <usr/amz_date.h>
#include <usr/aws_sigv4.h>
#include <usr/imdsv2.h>
#include <usr/json.h>

/** @file
 *
 * AWS Get Boot Credentials From Secret Command
 *
 */

/** "aws_get_boot_credentials_from_secret" options */
struct aws_get_boot_creds_from_secret_options {
	/** Use the ipv4 IMDS address **/
	int ipv4;
	/** Use the ipv6 IMDS address **/
	int ipv6;
};

/** "aws_get_boot_creds_from_secret" option list */
static struct option_descriptor aws_get_boot_creds_from_secret_opts[] = {
	OPTION_DESC ( "ipv4", '4', no_argument,
				  struct aws_get_boot_creds_from_secret_options, ipv4, parse_flag ),
	OPTION_DESC ( "ipv6", '6', no_argument,
				  struct aws_get_boot_creds_from_secret_options, ipv6, parse_flag ) };

/** "aws_get_boot_creds_from_secret" command descriptor */
static struct command_descriptor aws_get_boot_creds_from_secret_cmd =
	COMMAND_DESC ( struct aws_get_boot_creds_from_secret_options,
				   aws_get_boot_creds_from_secret_opts, 1, 1,
				   "<chap_secret_name_or_arn>" );

/**
 * "aws_get_boot_creds_from_secret" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int aws_get_boot_creds_from_secret_exec ( int argc, char **argv ) {
	struct aws_get_boot_creds_from_secret_options opts = { 0 };
	const char *chap_secret_id;
	const char *base_url;
	char *imdsv2_token = NULL;
	char *region = NULL;
	char *instance_role = NULL;
	char *iam_role_metadata_path = NULL;
	char *credentials = NULL;
	char *access_key = NULL;
	char *secret_access_key = NULL;
	char *session_token = NULL;
	char *chap_payload = NULL;
	DateTime date_time;
	char *amz_date = NULL;
	char *date_stamp = NULL;
	char *sigv4 = NULL;
	struct uri *uri = NULL;
	char *response = NULL;
	json_kv userid_kv = { NULL, NULL };
	json_kv password_kv = { NULL, NULL };
	json_kv mutual_userid_kv = { NULL, NULL };
	json_kv mutual_password_kv = { NULL, NULL };
	struct named_setting setting;
	int rc;

	/* Parse options */
	rc = parse_options ( argc, argv, &aws_get_boot_creds_from_secret_cmd, &opts );
	if ( rc != 0 ) {
		goto err_parse_options;
	}

	/* Check for invalid flag combination */
	if ( opts.ipv4 && opts.ipv6 ) {
		printf ( "Error: Cannot specify both IPv4 and IPv6 flags\n" );
		rc = -EINVAL;
		goto err_parse_options;
	}

	rc = get_imdsv2_metadata_base_url ( opts.ipv6, &base_url );
	if ( rc != 0 ) {
		goto err_base_url;
	}

	/* Parse CHAP secret name or ARN's */
	chap_secret_id = argv[optind];

	/* Get IMDSv2 session token */
	rc = get_imdsv2_token ( base_url, &imdsv2_token );
	if ( rc != 0 ) {
		goto err_get_imdsv2_token;
	}

	/* Get the region the EC2 instance is placed in */
	rc = get_imdsv2_metadata ( imdsv2_token, base_url, "meta-data/placement/region/", &region );
	if ( rc != 0 ) {
		goto err_get_region;
	}

	/* Get IAM Role associated with the EC2 Instance */
	rc = get_imdsv2_metadata ( imdsv2_token, base_url, "meta-data/iam/security-credentials/", &instance_role );
	if ( rc != 0 ) {
		printf ( "ERROR: Failed to retrieve IAM instance role via IMDSv2. Check instance profile configuration\n" );
		goto err_get_instance_role;
	}

	/* Build IAM Role metadata path */
	rc = url_concat ( "meta-data/iam/security-credentials/", instance_role, &iam_role_metadata_path );
	if ( rc != 0 ) {
		goto err_url_concat;
	}

	/* Get credentials associated with the IAM Role */
	rc = get_imdsv2_metadata ( imdsv2_token, base_url, iam_role_metadata_path, &credentials );
	if ( rc != 0 ) {
		goto err_get_credentials;
	}

	/* Extract the Access Key Id */
	rc = json_extract_string ( credentials, "AccessKeyId", &access_key );
	if ( rc != 0 ) {
		goto err_parse_access_key;
	}

	/* Extract the Secret Access Key */
	rc = json_extract_string ( credentials, "SecretAccessKey", &secret_access_key );
	if ( rc != 0 ) {
		goto err_parse_secret_access_key;
	}

	/* Extract the Credential Session Token */
	rc = json_extract_string ( credentials, "Token", &session_token );
	if ( rc != 0 ) {
		goto err_parse_session_token;
	}

	/* Generate JSON payload for SigV4 */
	rc = generate_get_secret_value_payload ( chap_secret_id, &chap_payload );
	if ( rc != 0 ) {
		goto err_chap_payload;
	}

	/* Get current date */
	time_t raw_time = time ( NULL );
	epoch_to_datetime ( raw_time, &date_time );

	/* Get the amz_date for SigV4 */
	rc = format_amz_date ( &date_time, &amz_date );
	if ( rc != 0 ) {
		goto err_amz_date;
	}

	/* Get the date_stamp for SigV4 */
	rc = format_date_stamp ( &date_time, &date_stamp );
	if ( rc != 0 ) {
		goto err_date_stamp;
	}

	/* Calculate AWS Sigv4 */
	AwsSigv4Params params = {
		.payload = chap_payload,
		.service = "secretsmanager",
		.operation = "GetSecretValue",
		.region = region,
		.amz_date = amz_date,
		.date_stamp = date_stamp,
		.access_key = access_key,
		.secret_key = secret_access_key,
		.session_token = session_token };
	rc = aws_sigv4 ( &params, &sigv4 );
	if ( rc != 0 ) {
		printf ( "Error: Failed to generate SigV4 signature for Secrets Manager request. \n" );
		goto err_sigv4;
	}

	/* Generate SecretsManger request */
	rc = generate_aws_request ( &params, sigv4, chap_payload, &uri );
	if ( rc != 0 ) {
		goto err_request;
	}

	/* Send the request */
	rc = download_and_get_string ( uri, &response );
	if ( rc != 0 ) {
		goto err_download;
	}

	/* Set username */
	rc = parse_and_store_credential ( response, &userid_kv, "userid", &setting, "username" );
	if ( rc != 0 ) {
		goto err_parse_userid;
	}

	/* Set password */
	rc = parse_and_store_credential ( response, &password_kv, "password", &setting, "password" );
	if ( rc != 0 ) {
		goto err_parse_password;
	}

	/* Optionally set reverse-username */
	rc = parse_and_store_credential ( response, &mutual_userid_kv, "mutual_userid",
									  &setting, "reverse-username" );

	/* Optionally set reverse-password */
	rc = parse_and_store_credential ( response, &mutual_password_kv, "mutual_password",
									  &setting, "reverse-password" );

	/* If reverse chap credentials could not be found or parsed then proceed with one way chap*/
	if ( rc != 0 ) {
		printf ( "Reverse chap credentials not found. Configuring one way chap.\n" );
	} else {
		printf ( "Reverse chap credentials found. Configuring mutual chap.\n" );
	}

	free ( mutual_password_kv.key );
	free ( mutual_password_kv.value );
	free ( mutual_userid_kv.key );
	free ( mutual_userid_kv.value );
	free ( password_kv.key );
	free ( password_kv.value );
	free ( userid_kv.key );
	free ( userid_kv.value );
	free ( response );
	claim_parameters ( uri->params );
	params_put ( uri->params );
	uri_put ( uri );
	free ( sigv4 );
	free ( date_stamp );
	free ( amz_date );
	free ( chap_payload );
	free ( session_token );
	free ( secret_access_key );
	free ( access_key );
	free ( credentials );
	free ( iam_role_metadata_path );
	free ( instance_role );
	free ( region );
	free ( imdsv2_token );
	return 0;

err_parse_password:
	free ( password_kv.key );
	free ( password_kv.value );
err_parse_userid:
	free ( userid_kv.key );
	free ( userid_kv.value );
err_download:
	free ( response );
err_request:
	claim_parameters ( uri->params );
	params_put ( uri->params );
	uri_put ( uri );
err_sigv4:
	free ( sigv4 );
err_date_stamp:
	free ( date_stamp );
err_amz_date:
	free ( amz_date );
err_chap_payload:
	free ( chap_payload );
err_parse_session_token:
	free ( session_token );
err_parse_secret_access_key:
	free ( secret_access_key );
err_parse_access_key:
	free ( access_key );
err_get_credentials:
	free ( credentials );
err_url_concat:
	free ( iam_role_metadata_path );
err_get_instance_role:
	free ( instance_role );
err_get_region:
	free ( region );
err_get_imdsv2_token:
	free ( imdsv2_token );
err_base_url:
err_parse_options:
	return rc;
}

/** AWS get boot credentials from secret command */
struct command aws_get_boot_creds_from_secret __command = {
	.name = "aws_get_boot_creds_from_secret",
	.exec = aws_get_boot_creds_from_secret_exec,
};
