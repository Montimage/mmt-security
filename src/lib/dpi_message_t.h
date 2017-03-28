/*
 * dpi_message_t.h
 *
 * Bridging the gap between mmt-dpi data and mmt-security message
 *
 *  Created on: Mar 24, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_DPI_MESSAGE_T_H_
#define SRC_LIB_DPI_MESSAGE_T_H_


#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>

#include "message_t.h"

#ifndef ftp_command_struct
/**
 * FTP command structure: CMD PARAMETER
 */
typedef struct ftp_command_struct{
	uint16_t cmd;
	char *str_cmd;
	char *param;
}ftp_command_t;

/**
 * FTP response structure
 */
typedef struct ftp_response_struct{
	uint16_t code;
	char *str_code;
	char *value;
}ftp_response_t;

#endif

/**
 * Get length of payload of a protocol
 * @param ipacket
 * @param proto_id
 * @return
 */
static inline size_t dpi_get_payload_len(const ipacket_t * ipacket, uint32_t proto_id ){
	int  j = 0;
	uint16_t length = 0;
	uint16_t offset = 0;

	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset +=ipacket->proto_headers_offset->proto_path[j];

		if ( ipacket->proto_hierarchy->proto_path[j] == proto_id ){
			if ( (j+1) < ipacket->proto_hierarchy->len){
				offset +=ipacket->proto_headers_offset->proto_path[j+1];
				length = ipacket->p_hdr->caplen - offset;

				return length;
			}
		}
	}

	return 0;
}

/**
 * Get length of data of a protocol
 * @param ipacket
 * @param proto_id
 * @return
 */
static inline size_t dpi_get_data_len( const ipacket_t * ipacket, uint32_t proto_id ){
	int  j = 0;

	uint16_t length = 0;
	uint16_t offset = 0;

	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset +=ipacket->proto_headers_offset->proto_path[j];
		if ( ipacket->proto_hierarchy->proto_path[j] == proto_id ){
			length = ipacket->p_hdr->caplen - offset;

			return length;
		}
	}
	return 0;
}

static inline size_t dpi_get_ip_option_len(const ipacket_t * ipacket ){
	int  j = 0;
	uint16_t offset = 0;
	uint8_t length;
	int index;
	void *data;

	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset +=ipacket->proto_headers_offset->proto_path[j];
		if (ipacket->proto_hierarchy->proto_path[j] == PROTO_IP ){
			offset += ipacket->proto_headers_offset->proto_path[j+1];
			index = offset + 21; //option len start at 21th byte of IP header

			if( index <= 0 )
				return 0;

			length =  ((uint8_t* ) ipacket->data)[ index ];
			if( length + index > ipacket->p_hdr->caplen ){
				//mmt_warn( "Error when getting ip.options or %"PRIu64"-th packet is mal-formatted", ipacket->packet_id );
				return 0;
			}

			return length;
		}
	}
	return 0;
}


/**
 * Public API
 * Convert data in format of MMT-Probe to data in format of MMT-Sec
 */
static inline int dpi_message_set_void_data( const ipacket_t *pkt, const void *data, message_t *msg, message_element_t *el ){
	const void *new_data = NULL;
	size_t new_data_len  = 0;
	int new_data_type    = VOID;

	switch( el->att_id ){
	case PROTO_PAYLOAD:
		new_data_type = VOID;
		new_data      = data;
		new_data_len  = dpi_get_payload_len( pkt, el->proto_id );
		break;

	case PROTO_DATA:
		new_data_type = VOID;
		new_data      = data;
		new_data_len  = dpi_get_data_len( pkt, el->proto_id );
		break;

	case FTP_LAST_COMMAND:
		if ( el->proto_id == PROTO_FTP ){
			new_data_type = STRING;
			new_data      = ((ftp_command_t *)data)->str_cmd;
			new_data_len  = strlen( ((ftp_command_t *)data)->str_cmd );
		}
		break;

	case FTP_LAST_RESPONSE_CODE:
		if ( el->proto_id == PROTO_FTP ){
			new_data_type = STRING;
			new_data      = ((ftp_response_t *)data)->str_code;
			new_data_len  = strlen( ((ftp_response_t *)data)->str_code );
		}
		break;

	case IP_OPTS:
		if( el->proto_id == PROTO_IP){
			new_data_type = VOID;
			new_data      = data;
			new_data_len  = dpi_get_ip_option_len( pkt );
		}
		break;

	default:
		mmt_warn("Need to process attribute %d.%d for packet %"PRIu64, el->proto_id, el->att_id, pkt->packet_id );
		break;
	}//end of switch( att_id )

	if( new_data_len == 0 || new_data == NULL )
		return 0;

	el->data_type = new_data_type;
	return set_data_of_one_element_message_t( msg, el, new_data, new_data_len );
}

/**
 * Convert data encoded in a pcap packet to readable data that is either a double
 * or a string ending by '\0'.
 * This function will create a new memory segment to store its result.
 */
static inline int dpi_message_set_data( const ipacket_t *pkt, int data_type, message_t *msg, message_element_t *el ){
	double number       = 0;
	uint8_t *data       = (uint8_t *) get_attribute_extracted_data( pkt, el->proto_id, el->att_id );
	const void *new_data= NULL;
	size_t new_data_len = 0;
	int new_data_type   = VOID;

	//does not exist data for this proto_id and att_id
	if( data == NULL )
		return 1;

	if( data_type == MMT_DATA_POINTER ){
		return dpi_message_set_void_data( pkt, data, msg, el );
	}

	return set_dpi_data_to_one_element_message_t( data, data_type, msg, el );
}

#endif /* SRC_LIB_DPI_MESSAGE_T_H_ */
