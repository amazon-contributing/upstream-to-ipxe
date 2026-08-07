#ifndef _USR_AWS_DATE_H
#define _USR_AWS_DATE_H

/** @file
 *
 * Amazon-style date and time formatting for AWS SigV4
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <time.h>

/** A calendar date and time */
struct date_time {
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
};

extern void epoch_to_datetime ( time_t epochs, struct date_time *dt );
extern int format_amz_date ( struct date_time *dt, char **amz_date );
extern int format_date_stamp ( struct date_time *dt, char **date_stamp );

#endif /* _USR_AWS_DATE_H */
