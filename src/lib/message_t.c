/*
 * message_t.c
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "message_t.h"
#include "mmt_lib.h"
#include "expression.h"
#include "mmt_mem_pool.h"

#include "../dpi/types_defs.h"
//
//static pthread_spinlock_t spin_lock;
//
//__attribute__((constructor)) void _constructor () {
//	mmt_assert( pthread_spin_init ( &spin_lock, 0 ) == 0, "Cannot init spinlock for message_t" );
//}
//


static __thread mmt_mem_pool_t *mem_pool = NULL;

message_t *create_message_t( size_t elements_count ){
	int i;
//	if( unlikely( mem_pool == NULL ))
//		mem_pool = mmt_mem_pool_create( sizeof( message_t ) + sizeof( message_element_t) * elements_count, 1000 );

	message_t *msg;

//	msg = mmt_mem_pool_allocate_element( mem_pool, mmt_mem_alloc );
	msg = mmt_mem_alloc( sizeof( message_t ) + sizeof( message_element_t) * elements_count  + get_config()->input.max_report_size );


	msg->elements_count = elements_count;
	msg->elements       = (message_element_t *) (&msg[1]); //store elements at the same date segment with msg
	for( i=0; i<msg->elements_count; i++ ){
		msg->elements[i].data = NULL;
	}

	msg->hash         = 0;
	msg->_data_index  = sizeof( message_t ) + sizeof( message_element_t) * elements_count;
	msg->_data        = ((uint8_t *) msg) + msg->_data_index;
	msg->_data_length = get_config()->input.max_report_size;
	return msg;
}

void force_free_message_t( message_t *msg ){
//	size_t i;
//	for( i=0; i<msg->elements_count; i++ )
//		if( likely( msg->elements[i].data != NULL ))
//			mmt_mem_force_free( msg->elements[i].data );

//	mmt_mem_pool_free_element( mem_pool, msg, mmt_mem_force_free );
	mmt_mem_force_free( msg );
}


size_t free_message_ts( message_t *msg, uint16_t size ){
	size_t ret;
	__check_null( msg, 0 );  // nothing to do

	mmt_memory_t *mem = mmt_mem_revert( msg );

	//free message only when there is no more reference to it
	if( mem->ref_count <= size ){
		mmt_mem_force_free( msg );
		return 0;
	}

	ret = __sync_sub_and_fetch( &mem->ref_count, size );

	return ret;
}

/**
 * public API
 * @param msg
 * @param elem
 * @param data
 * @param length
 * @return
 */
int set_data_of_one_element_message_t( message_t *msg, message_element_t *elem, const void *data, size_t length ){
	mmt_memory_t *mem;
	if( unlikely (msg->_data_index + length + SIZE_OF_MMT_MEMORY_T  >= msg->_data_length )){
		mmt_warn( "Report for %d.%d is too big (%zu bytes), must increase config.input.max_report_size",
				elem->proto_id, elem->att_id,
				length + SIZE_OF_MMT_MEMORY_T);
		return MSG_OVERFLOW;
	}else if( length == 0 ){
		elem->data = NULL;
		return 0;
	}

	//convert to mmt_memory_t
	mem = (mmt_memory_t *) &msg->_data[ msg->_data_index ];
	mmt_mem_reset( mem, length );

	elem->data = mem->data;
	memcpy( elem->data, data, length );

	msg->_data_index += length + SIZE_OF_MMT_MEMORY_T;

	//update hash to mark the present of elem->data
	msg->hash |= elem->proto_id | elem->att_id;

	return MSG_CONTINUE;
}

/**
 * Convert data encoded by mmt-dpi to one element of message_t.
 * - Input:
 * 	+ data    : data to be converted
 * 	+ type    : type of #data
 * - Output:
 * 	+ el  : element to be updated in message_t
 * 	+ msg : message containing el
 * - return:
 * 	+ 0 if success
 */
int set_dpi_data_to_one_element_message_t( const void *data, int data_type, message_t *msg, message_element_t *el ){
	double number       = 0;
	const void *new_data= NULL;
	size_t new_data_len = 0;
	int new_data_type   = VOID;

	//does not exist data for this proto_id and att_id
	if( data == NULL )
		return 1;

	switch( data_type ){
	case MMT_UNDEFINED_TYPE: /**< no type constant value */
		break;
	case MMT_DATA_CHAR: /**< 1 character constant value */
		number = *(char *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_U8_DATA: /**< unsigned 1-byte constant value */
		number    = *(uint8_t *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_DATA_PORT: /**< tcp/udp port constant value */
	case MMT_U16_DATA: /**< unsigned 2-bytes constant value */
		number    = *(uint16_t *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_U32_DATA: /**< unsigned 4-bytes constant value */
		number    = *(uint32_t *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_U64_DATA: /**< unsigned 8-bytes constant value */
		number    = *(uint64_t *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_DATA_FLOAT: /**< float constant value */
		number   =  *(float *) data;
		new_data_type = NUMERIC;
		new_data      = &number;
		new_data_len  = sizeof( double );
		break;

	case MMT_DATA_IP6_ADDR: /**< ip6 address constant value */
	case MMT_DATA_MAC_ADDR: /**< ethernet mac address constant value */
		new_data_type = VOID;
		new_data      = data;
		new_data_len  = 6;
		break;

	case MMT_DATA_IP_NET: /**< ip network address constant value */
	case MMT_DATA_IP_ADDR: /**< ip address constant value */
		new_data_type = VOID;
		new_data      = data;
		new_data_len  = 4;
		break;

	case MMT_DATA_POINTER: /**< pointer constant value (size is void *) */
	case MMT_DATA_PATH: /**< protocol path constant value */
	case MMT_DATA_TIMEVAL: /**< number of seconds and microseconds constant value */
	case MMT_DATA_BUFFER: /**< binary buffer content */
	case MMT_DATA_POINT: /**< point constant value */
	case MMT_DATA_PORT_RANGE: /**< tcp/udp port range constant value */
	case MMT_DATA_DATE: /**< date constant value */
	case MMT_DATA_TIMEARG: /**< time argument constant value */
	case MMT_DATA_STRING_INDEX: /**< string index constant value (an association between a string and an integer) */
	case MMT_DATA_LAYERID: /**< Layer ID value */
	case MMT_DATA_FILTER_STATE: /**< (filter_id: filter_state) */
	case MMT_DATA_PARENT: /**< (filter_id: filter_state) */
	case MMT_STATS: /**< pointer to MMT Protocol statistics */
	case MMT_BINARY_DATA: /**< binary constant value */
		break;
	case MMT_BINARY_VAR_DATA: /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
	case MMT_STRING_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
	case MMT_STRING_LONG_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
		new_data_type = STRING;
		new_data      = ((mmt_binary_var_data_t *)data)->data;
		new_data_len  = ((mmt_binary_var_data_t *)data)->len;
		break;


	case MMT_HEADER_LINE: /**< string pointer value with a variable size. The string is not necessary null terminating */
		new_data_type = STRING;
		new_data      = ((mmt_header_line_t *)data)->ptr;
		new_data_len  = ((mmt_header_line_t *)data)->len;
		break;

	case MMT_GENERIC_HEADER_LINE: /**< structure representing an RFC2822 header line with null terminating field and value elements. */
	case MMT_STRING_DATA_POINTER: /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
		new_data_type = STRING;
		new_data      = data;
		new_data_len  = strlen( (char*) data);
		break;

	default:
		break;
	}

	if( new_data_len == 0 || new_data == NULL )
		return 0;

	el->data_type = new_data_type;
	return set_data_of_one_element_message_t( msg, el, new_data, new_data_len );
}

//__attribute__((destructor)) void _destructor () {
//	mmt_mem_pool_free( mem_pool );

//}
