/*
 *  Copyright (C) 2014 Motorola, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Adds ability to program periodic interrupts from user space that
 *  can wake the phone out of low power modes.
 *
 */

#ifndef _M4SENSORHUB_PASSIVE_IIO_H
#define _M4SENSORHUB_PASSIVE_IIO_H

enum m4sensorhub_passive_iio_type {
	PASSIVE_TYPE_EVENT_DATA = 0,
	PASSIVE_TYPE_EVENT_FLUSH = 1,
	PASSIVE_TYPE_EVENT_NONE = 2,
};

struct m4sensorhub_passive_event_data {
	uint32_t        passive_timestamp;
	uint16_t        steps;
	uint16_t        calories;
	uint16_t        heartrate;
	uint8_t         hrconfidence;
	uint8_t         healthy_minutes;
} __packed;

struct m4sensorhub_passive_iio_data {
	uint8_t type;
	struct m4sensorhub_passive_event_data event_data;
	long long       timestamp;
} __packed;

#define M4PAS_DRIVER_NAME           "m4sensorhub_passive"
#define M4PAS_DATA_STRUCT_SIZE_BITS \
	(sizeof(struct m4sensorhub_passive_iio_data) * 8)

#define M4PAS_NUM_PASSIVE_BUFFERS   12

#endif /* _M4SENSORHUB_PASSIVE_IIO_H */
