/*
 *   Copyright (C) 2016, VASCO Data Security Int.
 *   Author: Johan.Verrept@vasco.com
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _FIDO_BLE_H_
#define _FIDO_BLE_H_

#define FIDO_SERVICE_SHORTUUID	0xFFFD

#define TYPE_MASK               0x80	// Frame type mask
#define TYPE_INIT               0x80	// Initial frame identifier
#define TYPE_CONT               0x00	// Continuation frame identifier

#define FIDO_BLE_CMD_PING			(TYPE_INIT | 0x01)
#define FIDO_BLE_CMD_KEEPALIVE			(TYPE_INIT | 0x02)
#define	FIDO_BLE_CMD_MSG			(TYPE_INIT | 0x03)
#define	FIDO_BLE_CMD_ERROR			(TYPE_INIT | 0x3F)

#define ERR_NONE  		0
#define ERR_INVALID_CMD  	1
#define ERR_INVALID_PAR  	2
#define ERR_INVALID_LEN  	3
#define ERR_INVALID_SEQ  	4
#define ERR_MSG_TIMEOUT  	5
#define ERR_OTHER  		127

#endif
