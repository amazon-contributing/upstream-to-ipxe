#ifndef _USR_IMDSV2_H
#define _USR_IMDSV2_H

#include <ipxe/image.h>

/** @file
 *
 * AWS Instance Metadata Service (IMDSv2) helper commands
 *
 */

extern int get_image_data ( struct image *image, char **buffer );
extern int url_concat ( const char *base_url, const char *path, char **url );
extern int download_and_get_string ( struct uri *uri, char **result );
extern int get_imdsv2_token ( const char *base_url, char **token );
extern int get_imdsv2_metadata ( char *token, const char *base_url, char *metadata_path, char **response );
extern int get_imdsv2_metadata_base_url ( int use_ipv6, const char **base_url );

#define IMDSV2_IPV4_METADATA_BASE_URL "http://169.254.169.254/latest/"
#define IMDSV2_IPV6_METADATA_BASE_URL "http://[fd00:ec2::254]/latest/"

#endif /* _USR_IMDSV2_H */
