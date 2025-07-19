#include <errno.h>
#include <ipxe/image.h>
#include <ipxe/malloc.h>
#include <ipxe/uri.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <usr/imdsv2.h>
#include <usr/imgmgmt.h>
#include <usr/userdata.h>

/**
 * Concatenates two URL parts, handling potential slash issues.
 *
 * @v base_url      The base URL string.
 * @v path          The path URL string to append.
 * @v url			Pointer to a char pointer that will receive the allocated concatenated URL string
 * @ret rc			Return status code
 */
int url_concat ( const char *base_url, const char *path, char **url ) {
	if ( ! base_url || ! path ) {
		return -EINVAL;
	}

	size_t base_len = strlen ( base_url );
	size_t path_len = strlen ( path );
	/* total_len has + 2 for the null terminator plus a potential '/' */
	size_t total_len = base_len + path_len + 2;

	char *result = malloc ( total_len );
	if ( ! result ) {
		return -ENOMEM;
	}

	strcpy ( result, base_url );

	bool base_ends_slash = base_len > 0 && base_url[base_len - 1] == '/';
	bool path_starts_slash = path_len > 0 && path[0] == '/';

	if ( path_len > 0 ) {
		if ( ! base_ends_slash && ! path_starts_slash ) {
			/* Add a '/' inbetween the base url and the path */
			strcat ( result, "/" );
		} else if ( base_ends_slash && path_starts_slash ) {
			/* Remove a '/' fromn the base url */
			result[base_len - 1] = '\0';
		}
		strcat ( result, path );
	}

	*url = result;

	return 0;
}

/**
 * Copy image data to a buffer
 *
 * @v image		Image to read
 * @v buffer 	Buffer to fill in
 * @ret rc      Return status code
 */
int get_image_data ( struct image *image, char **buffer ) {
	/* Initialize output parameter */
	*buffer = NULL;

	size_t offset = 0;

	/* Allocate a buffer to hold the data */
	*buffer = malloc ( image->len + 1 );
	if ( ! *buffer ) {
		return -ENOMEM;
	}

	/* Copy data from userptr_t to our local buffer */
	memcpy ( *buffer, ( image->data + offset ), image->len );

	/* Null terminate the buffer */
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
	rc = imgdownload ( uri, 0, &image );
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
 * Get IMDSv2 session token
 *
 * @v token           Pointer to store the token string
 * @v base_url        The AWS IMDS ipv4 or ipv6 base url
 * @ret rc            Return status code
 */
int get_imdsv2_token ( const char *base_url, char **token ) {
	char *uri_string = NULL;
	struct uri *uri = NULL;
	int rc;

	/* Initialize token to NULL */
	*token = NULL;

	/* Build IMDSv2 api token URI */
	rc = url_concat ( base_url, "api/token", &uri_string );
	if ( rc != 0 ) {
		goto err_url_concat;
	}

	/* Parse the URI string */
	uri = parse_uri ( uri_string );
	if ( uri == NULL ) {
		rc = -ENOMEM;
		goto err_uri_parse;
	}

	uri->method = &http_put;
	uri->aws_token_ttl = AWS_TOKEN_TTL;

	rc = download_and_get_string ( uri, token );
	if ( rc != 0 )
		goto err_download;

	free ( uri_string );
	uri_put ( uri );
	return 0;

err_download:
	uri_put ( uri );
err_uri_parse:
	free ( uri_string );
err_url_concat:
	return rc;
}

/**
 * Get metadata associated with an EC2 Instance using IMDSv2.
 *
 * @v token         The AWS IMDSv2 session token to include in the request header.
 * @v base_url   	The AWS IMDS ipv4 or ipv6 base url
 * @v metadata_path The specific metadata path to retrieve (e.g., "instance-id").
 * @v response      A pointer to a character pointer that will store the retrieved metadata string.
 */
int get_imdsv2_metadata ( char *token, const char *base_url, char *metadata_path, char **response ) {
	char *uri_string = NULL;
	struct uri *uri = NULL;
	int rc;

	/* Initialize response to NULL */
	*response = NULL;

	/* Build IMDSv2 metadata URI */
	rc = url_concat ( base_url, metadata_path, &uri_string );
	if ( rc != 0 ) {
		goto err_url_concat;
	}
	/* Parse the URI string */
	uri = parse_uri ( uri_string );
	if ( uri == NULL ) {
		rc = -ENOMEM;
		goto err_uri_parse;
	}

	uri->method = &http_get;
	uri->aws_token = token;

	rc = download_and_get_string ( uri, response );
	if ( rc != 0 ) {
		goto err_download;
	}

	free ( uri_string );
	uri_put ( uri );
	return 0;

err_download:
	uri_put ( uri );
err_uri_parse:
	free ( uri_string );
err_url_concat:
	return rc;
}

/**
 * Sets the appropriate IMDS base URL based on IP version preference.
 *
 * @v use_ipv6   Boolean flag to determine whether to use IPv6 (true) or IPv4 (false)
 * @v base_url   Pointer to a char pointer that will store the selected base URL
 *              Will be set to either IMDSV2_IPV6_METADATA_BASE_URL or IMDSV2_IPV4_METADATA_BASE_URL
 *
 * @ret rc      Return status code
 */
int get_imdsv2_metadata_base_url ( int use_ipv6, const char **base_url ) {
	if ( use_ipv6 ) {
		*base_url = IMDSV2_IPV6_METADATA_BASE_URL;
	} else {
		*base_url = IMDSV2_IPV4_METADATA_BASE_URL;
	}
	return 0;
}
