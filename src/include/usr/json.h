#ifndef _USR_JSON_H
#define _USR_JSON_H

/** @file
 *
 * Minimal JSON string extraction
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

extern int json_extract_string ( char *json, char *key, char **output );

#endif /* _USR_JSON_H */
