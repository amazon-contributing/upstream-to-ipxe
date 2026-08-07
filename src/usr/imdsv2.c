FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <errno.h>
#include <ipxe/image.h>
#include <ipxe/malloc.h>
#include <ipxe/params.h>
#include <ipxe/uri.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <usr/imdsv2.h>
#include <usr/imgmgmt.h>

/** @file
 *
 * AWS Instance Metadata Service (IMDSv2) helpers
 *
 */

/**
 * Copy image data to a NUL-terminated buffer
 *
 * @v image		Image to read
 * @v buffer 	Buffer to fill in
 * @ret rc      Return status code
 */
static int get_image_data ( struct image *image, char **buffer ) {
	/* Initialize output parameter */
	*buffer = NULL;

	/* Allocate a buffer to hold the data */
	*buffer = malloc ( image->len + 1 );
	if ( ! *buffer ) {
		return -ENOMEM;
	}

	/* Copy data from the image and NUL-terminate the buffer */
	memcpy ( *buffer, image->data, image->len );
	( *buffer )[image->len] = '\0';

	return 0;
}

int download_and_get_string ( struct uri *uri, char **result ) {
	int rc;
	struct image *image = NULL;

	/* Initialize output parameter */
	*result = NULL;

	/* Get our own reference */
	uri = uri_get ( uri );

	/* Download content into image */
	rc = imgdownload ( uri, 0, 0, &image );
	if ( rc != 0 )
		goto err_download;

	/* Convert image data to string */
	rc = get_image_data ( image, result );
	if ( rc != 0 )
		goto err_conversion;

	image_put ( image );
	return 0;

err_conversion:
	image_put ( image );
err_download:
	return rc;
}

/**
 * Fetch a resource from the EC2 Instance Metadata Service (IMDSv2)
 *
 * A single request either retrieves a new session token or reads a
 * metadata item using an existing token:
 *
 *   - @c token == NULL : PUT api/token, carrying the token TTL
 *     header; the response body is the new session token.
 *   - @c token != NULL : GET the metadata path, carrying the session
 *     token header.
 *
 * @v base_url		IMDS base URL (IPv4 or IPv6), ending in '/'
 * @v path		Resource path relative to @c base_url
 * @v token		Session token to present, or NULL to fetch one
 * @v result		Receives the response body (caller frees)
 * @ret rc		Return status code
 */
int get_imdsv2 ( const char *base_url, const char *path,
		 const char *token, char **result ) {
	char *uri_string = NULL;
	struct uri *uri = NULL;
	struct parameters *params = NULL;
	const char *method;
	const char *header_name;
	const char *header_value;
	int rc;

	/* Initialize output parameter */
	*result = NULL;

	/* Select the method and metadata-token header for this request.
	 * A tokenless request fetches a new token via PUT; any other
	 * request reads metadata via GET using the supplied token.
	 */
	if ( token == NULL ) {
		method = "PUT";
		header_name = "X-aws-ec2-metadata-token-ttl-seconds";
		header_value = AWS_TOKEN_TTL;
	} else {
		method = "GET";
		header_name = "X-aws-ec2-metadata-token";
		header_value = token;
	}

	/* Build the request URI.  The base URL ends in '/', so the
	 * relative path appends without a separator.
	 */
	if ( asprintf ( &uri_string, "%s%s", base_url, path ) < 0 ) {
		rc = -ENOMEM;
		goto err_asprintf;
	}
	uri = parse_uri ( uri_string );
	if ( uri == NULL ) {
		rc = -ENOMEM;
		goto err_parse_uri;
	}

	/* Build the request parameter list carrying the method and the
	 * metadata-token header.  The list is anonymous (NULL name);
	 * create_parameters() destroys any existing list of the same
	 * name, so claim it out of the global registry immediately and
	 * hand ownership to the URI, which releases it via uri_put().
	 */
	params = create_parameters ( NULL, method );
	if ( params == NULL ) {
		rc = -ENOMEM;
		goto err_create_parameters;
	}
	uri->params = claim_parameters ( params );
	if ( add_parameter ( uri->params, header_name, header_value,
			     PARAMETER_HEADER ) == NULL ) {
		rc = -ENOMEM;
		goto err_add_parameter;
	}

	/* Issue the request */
	rc = download_and_get_string ( uri, result );
	if ( rc != 0 )
		goto err_download;

	uri_put ( uri );
	free ( uri_string );
	return 0;

err_download:
err_add_parameter:
err_create_parameters:
	uri_put ( uri );
err_parse_uri:
	free ( uri_string );
err_asprintf:
	return rc;
}
