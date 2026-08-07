#ifndef _USR_IMDSV2_H
#define _USR_IMDSV2_H

/** @file
 *
 * AWS Instance Metadata Service (IMDSv2) helpers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/image.h>

extern int download_and_get_string ( struct uri *uri, char **result );
extern int get_imdsv2 ( const char *base_url, const char *path,
			const char *token, char **result );

#define IMDSV2_IPV4_METADATA_BASE_URL "http://169.254.169.254/latest/"
#define IMDSV2_IPV6_METADATA_BASE_URL "http://[fd00:ec2::254]/latest/"

/** Default TTL (Time To Live) value for AWS tokens in seconds */
#define AWS_TOKEN_TTL "21600"

#endif /* _USR_IMDSV2_H */
