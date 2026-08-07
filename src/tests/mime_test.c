/*
 * Copyright (C) 2026 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * MIME image tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <ipxe/image.h>
#include <ipxe/mime.h>
#include <ipxe/script.h>
#include <ipxe/test.h>
#include "archive_test.h"

/** "Hello world" */
ARCHIVE_TEST ( hello_world, &mime_image_type, "hw.mime", NULL, "hw",
	TEXTFILE ( "Content-Type: text/x-ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "Content-Transfer-Encoding: base64\r\n"
		   "Content-Disposition: attachment; filename=\"hw.ipxe\"\r\n"
		   "\r\n"
		   "IyFpcHhlCgplY2hvIEhlbGxvIHdvcmxkCnNoZWxsCg==\r\n" ),
	TEXTFILE ( "#!ipxe\n"
		   "\n"
		   "echo Hello world\n"
		   "shell\n" ) );

/** Multipart test */
ARCHIVE_TEST ( multipart, &mime_image_type, "user-data", NULL, "user-data",
	TEXTFILE ( "Content-Type: multipart/mixed; "
		       "boundary=\"===============5227682047807177400==\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "--===============5227682047807177400==\r\n"
		   "Content-Type: text/cloud-config; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "Content-Transfer-Encoding: base64\r\n"
		   "Content-Disposition: attachment; filename=\"conf.yml\"\r\n"
		   "\r\n"
		   "LS0tCmNvbmZpZzoKICB0aGluZ3M6CiAgICAtIG9uZQogICAgLSB0d2\r\n"
		   "8KICBvdGhlcnRoaW5nOiAid29vaG9vIgo=\r\n"
		   "\r\n"
		   "--===============5227682047807177400==\r\n"
		   "Content-Type: text/x-ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "Content-Transfer-Encoding: base64\r\n"
		   "Content-Disposition: attachment; filename=\"hw.ipxe\"\r\n"
		   "\r\n"
		   "IyFpcHhlCgplY2hvIEhlbGxvIHdvcmxkCnNoZWxsCg==\r\n"
		   "\r\n"
		   "--===============5227682047807177400==--\r\n" ),
	TEXTFILE ( "Content-Type: text/x-ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "Content-Transfer-Encoding: base64\r\n"
		   "Content-Disposition: attachment; filename=\"hw.ipxe\"\r\n"
		   "\r\n"
		   "IyFpcHhlCgplY2hvIEhlbGxvIHdvcmxkCnNoZWxsCg==\r\n"
		   "\r\n" ) );

/** No explicit encoding */
ARCHIVE_TEST ( no_encoding, &mime_image_type, "noenc.mime", NULL, "noenc",
	TEXTFILE ( "Content-Type: text/x-ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "#!ipxe\r\n"
		   "echo Default encoding\r\n" ),
	TEXTFILE ( "#!ipxe\r\n"
		   "echo Default encoding\r\n" ) );

/** Multipart with "text/ipxe" part preceded by an unrecognised part
 *
 * Mirrors the canonical EC2 launch wizard template shape: quoted
 * boundary, a text/part-handler part ahead of the text/ipxe part, and
 * charset attributes on the content types.
 */
ARCHIVE_TEST ( multipart_text_ipxe, &mime_image_type, "user-data2", NULL,
	"user-data2",
	TEXTFILE ( "Content-Type: multipart/mixed; "
		       "boundary=\"==BOUNDARY==\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "--==BOUNDARY==\r\n"
		   "Content-Type: text/part-handler; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "def handle(data):\n"
		   "    pass\n"
		   "\r\n"
		   "--==BOUNDARY==\r\n"
		   "Content-Type: text/ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "#!ipxe\n"
		   "echo Hello world\n"
		   "\r\n"
		   "--==BOUNDARY==--\r\n" ),
	TEXTFILE ( "Content-Type: text/ipxe; charset=\"utf-8\"\r\n"
		   "MIME-Version: 1.0\r\n"
		   "\r\n"
		   "#!ipxe\n"
		   "echo Hello world\n"
		   "\r\n" ) );

/** A user-data shape test
 *
 * These fixtures replicate the user-data payload shapes rendered by
 * the EC2 external storage launch wizard templates.  Each
 * pins the image type selected for the shape and, where applicable,
 * verifies the complete extraction chain from raw payload to an
 * executable plain script, following image type probes and recursive
 * extraction exactly as image_extract_exec() would at boot time.
 * The single-part template renders a blank line ahead of the
 * "#!ipxe" shebang, tolerated by the leading-whitespace skip in the
 * script probe; the templates emit no Content-Transfer-Encoding
 * header, so MIME entity extraction relies on matching the implicit
 * default ("7bit" identity) encoding.  Such user-data is already
 * deployed in the wild and cannot be regenerated.
 */
struct shape_test {
	/** Image data (NUL-terminated text) */
	const char *data;
	/** Expected image type after probe, or NULL for none */
	const struct image_type *type;
	/** Expected final extracted script, or NULL to check type only */
	const char *script;
};

/** Maximum extraction chain depth */
#define SHAPE_MAX_DEPTH 4

/** Define a user-data shape test */
#define SHAPE_TEST( _name, _data, _type, _script )	\
	static struct shape_test _name = {		\
		.data = _data,				\
		.type = _type,				\
		.script = _script,			\
	}

/** Plain script with shebang at offset zero */
SHAPE_TEST ( shebang_at_zero,
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n",
	     &script_image_type, NULL );

/** Single-part launch wizard shape: leading blank line before shebang */
SHAPE_TEST ( leading_newline,
	     "\n"
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n",
	     &script_image_type, NULL );

/** CRLF blank line before shebang */
SHAPE_TEST ( crlf_leading_newline,
	     "\r\n"
	     "#!ipxe\r\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\r\n",
	     &script_image_type, NULL );

/** Non-whitespace preamble: deliberately not accepted
 *
 * The retired user-data parser accepted arbitrary text ahead of the
 * shebang; no launch wizard template has ever rendered such a shape,
 * and the script probe tolerates only whitespace.
 */
SHAPE_TEST ( arbitrary_preamble,
	     "Some instructive text that precedes the script.\n"
	     "\n"
	     "#!ipxe\n"
	     "echo Booting\n",
	     NULL, NULL );

/** Single-entity MIME "text/ipxe" with no Content-Transfer-Encoding
 *
 * Entity extraction must succeed with the implicit default ("7bit"
 * identity) encoding and yield the plain script.
 */
SHAPE_TEST ( single_entity_ipxe,
	     "Content-Type: text/ipxe; charset=\"utf-8\"\n"
	     "MIME-Version: 1.0\n"
	     "\n"
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n",
	     &mime_image_type,
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n" );

/** Canonical multipart launch wizard shape, extracted to a script
 *
 * The chain is two extractions deep: multipart to entity (a MIME
 * image containing the part headers), then entity to script via the
 * implicit default encoding.  The final script retains the newline
 * preceding the closing boundary marker.
 */
SHAPE_TEST ( multipart_to_script,
	     "Content-Type: multipart/mixed; boundary=\"==BOUNDARY==\"\n"
	     "MIME-Version: 1.0\n"
	     "\n"
	     "--==BOUNDARY==\n"
	     "Content-Type: text/part-handler; charset=\"utf-8\"\n"
	     "\n"
	     "def handle(data):\n"
	     "    pass\n"
	     "\n"
	     "--==BOUNDARY==\n"
	     "Content-Type: text/ipxe; charset=\"utf-8\"\n"
	     "\n"
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n"
	     "\n"
	     "--==BOUNDARY==--\n",
	     &mime_image_type,
	     "#!ipxe\n"
	     "sanboot iscsi:192.0.2.10::3260:1:iqn.2024-01.com.example:boot\n"
	     "\n" );

/** No shebang at all: claimed by no type */
SHAPE_TEST ( no_shebang,
	     "Just some text without any script in it.\n",
	     NULL, NULL );

/**
 * Report a user-data shape test result
 *
 * @v test		User-data shape test
 * @v file		Test code file
 * @v line		Test code line
 */
static void shape_okx ( struct shape_test *test, const char *file,
			unsigned int line ) {
	struct image *image;
	struct image *extracted;
	unsigned int depth;

	/* Construct image (excluding the terminating NUL, as per a
	 * downloaded image; the image core appends its own NUL).
	 */
	image = image_memory ( "shape", test->data, strlen ( test->data ) );
	okx ( image != NULL, file, line );

	/* Check probed type selection */
	okx ( image->type == test->type, file, line );

	/* Follow the extraction chain to a plain script, as
	 * image_extract_exec() would at boot time.
	 */
	for ( depth = 0 ; test->script && image &&
		      ( image->type != &script_image_type ) &&
		      image->type && image->type->extract &&
		      ( depth < SHAPE_MAX_DEPTH ) ; depth++ ) {
		if ( image_extract ( image, NULL, &extracted ) != 0 )
			extracted = NULL;
		unregister_image ( image );
		image = extracted;
		okx ( image != NULL, file, line );
	}

	/* Verify final script, if applicable */
	if ( test->script && image ) {
		okx ( image->type == &script_image_type, file, line );
		okx ( image->len == strlen ( test->script ), file, line );
		okx ( memcmp ( image->data, test->script,
			       image->len ) == 0, file, line );
	}

	/* Unregister final image */
	if ( image )
		unregister_image ( image );
}

/** Report a user-data shape probe test result */
#define shape_ok( test ) shape_okx ( test, __FILE__, __LINE__ )

/**
 * Perform mime self-test
 *
 */
static void mime_test_exec ( void ) {

	archive_ok ( &hello_world );
	archive_ok ( &multipart );
	archive_ok ( &no_encoding );
	archive_ok ( &multipart_text_ipxe );
	shape_ok ( &shebang_at_zero );
	shape_ok ( &leading_newline );
	shape_ok ( &crlf_leading_newline );
	shape_ok ( &arbitrary_preamble );
	shape_ok ( &single_entity_ipxe );
	shape_ok ( &multipart_to_script );
	shape_ok ( &no_shebang );
}

/** MIME self-test */
struct self_test mime_test __self_test = {
	.name = "mime",
	.exec = mime_test_exec,
};
