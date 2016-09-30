/*
 * rule.c
 *
 *  Created on: 20 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <stdio.h>
#include <errno.h>
#include <libxml/xmlreader.h>

#include "mmt_alloc.h"
#include "rule.h"
#include "mmt_log.h"

#define str_equal(X,Y) xmlStrcmp( X, (const xmlChar*)Y) == 0

void rule_free_an_event( rule_event_t *event, enum bool free_data){
	if( event == NULL ) return;
	if( free_data ){
		mmt_free_and_assign_to_null( event->description );
		expr_free_an_expression( event->expression, free_data );
	}
	mmt_free_and_assign_to_null( event );
}

//pre-define
void _free_rule_node( rule_node_t *node );
void rule_free_an_operator( rule_operator_t *operator, enum bool free_data){

	if( operator == NULL ) return;
	if( free_data ){
		mmt_free_and_assign_to_null( operator->description );
		mmt_free_and_assign_to_null( operator->delay );
		_free_rule_node( operator->context );
		_free_rule_node( operator->trigger );
	}
	mmt_free_and_assign_to_null( operator );
}

void _free_rule_node( rule_node_t *node ){
	if( node == NULL ) return;

	if( node->type == RULE_EVENT )
		rule_free_an_event( node->event, YES );
	else if( node->type == RULE_OPERATOR )
		rule_free_an_operator( node->operator, YES );
	else{
		mmt_debug("Unexpected rule_node_type: %d", node->type );
	}
	mmt_free_and_assign_to_null( node );
}

void free_a_rule( rule_t *rule, enum bool free_data){
	if( rule == NULL )
		return;
	if( free_data ){
		mmt_free_and_assign_to_null( rule->description );
		mmt_free_and_assign_to_null( rule->delay );
		mmt_free_and_assign_to_null( rule->if_satisfied);
		mmt_free_and_assign_to_null( rule->if_not_satisfied );
		mmt_free_and_assign_to_null( rule->keep_state );
		_free_rule_node( rule->context );
		_free_rule_node( rule->trigger );
	}
	mmt_free_and_assign_to_null( rule );
}

/**
 * Create and init values for a delay struct
 */
rule_delay_t *_parse_rule_delay( const xmlNode *xml_node ){
	const xmlAttr *xml_attr;
	const xmlChar *xml_attr_name;
	xmlChar *xml_attr_value;

	rule_delay_t *delay = mmt_malloc( sizeof( rule_delay_t ));

	delay->time_min    = delay->time_max    = 0;
	delay->counter_min = delay->counter_max = 0;
	delay->time_unit   = SECOND;

	//parse attributes of the node
	xml_attr = xml_node->properties;
	while( xml_attr != NULL && xml_attr->name != NULL){
		xml_attr_name  = xml_attr->name;
		xml_attr_value = xmlGetProp( (xmlNodePtr) xml_node, xml_attr_name );

		if( str_equal( xml_attr_name, "delay_min" ) )
			delay->time_min = (uint8_t) atoll( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "delay_max" ) )
			delay->time_max = (uint8_t) atoll( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "counter_min" ) )
			delay->counter_min = (uint8_t) atoll( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "counter_max" ) )
			delay->counter_max= (uint8_t) atoll( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "delay_units" ) ){
			if( str_equal( xml_attr_value, "Y"))
				delay->time_unit = YEAR;
			else if( str_equal( xml_attr_value, "M"))
				delay->time_unit = MONTH;
			else if( str_equal( xml_attr_value, "D"))
				delay->time_unit = DAY;
			else if( str_equal( xml_attr_value, "H"))
				delay->time_unit = HOUR;
			else if( str_equal( xml_attr_value, "m"))
				delay->time_unit = MINUTE;
			else if( str_equal( xml_attr_value, "s"))
				delay->time_unit = SECOND;
			else if( str_equal( xml_attr_value, "ms"))
				delay->time_unit = MILI_SECOND;
			else if( str_equal( xml_attr_value, "mms"))
				delay->time_unit = MICRO_SECOND;
			else{
				mmt_assert(1, "Error 13d: Unexpected time_units: %s", xml_attr_value );
			}
		}
		xmlFree( xml_attr_value );
		xml_attr = xml_attr->next;
	}

	return delay;
}

static rule_event_t *_parse_an_event(const xmlNode *xml_node ){
	rule_event_t event, *ret = NULL;
	xmlAttr *xml_attr;
	const xmlChar *xml_attr_name;
	xmlChar *xml_attr_value;

	//init default values
	event.id          = UNKNOWN;
	event.description = NULL;
	event.expression  = NULL;

	//parse attributes of the node
	xml_attr = xml_node->properties;
	while( xml_attr != NULL && xml_attr->name != NULL){
		xml_attr_name  = xml_attr->name;
		xml_attr_value = xmlGetProp( (xmlNodePtr) xml_node, xml_attr_name );

		//for each attribute
		if( str_equal( xml_attr_name, "boolean_expression" ) )
			parse_expression( &event.expression, (const char *) xml_attr_value, strlen( (const char*) xml_attr_value ) );
		else if( str_equal( xml_attr_name, "description" ) )
			event.description = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		else if( str_equal( xml_attr_name, "event_id" ) )
			event.id = atoi( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "value" ) ){
			//do nothing
		}else
			mmt_log(WARN, "Warning 13e: Unexpected attribute %s in tag event", xml_attr_name );

		xmlFree( xml_attr_value );
		xml_attr = xml_attr->next;
	}

	ret = mmt_mem_dup( &event, sizeof( rule_event_t ));
	return ret;
}

//pre-define this function
static rule_node_t *_parse_a_rule_node( const xmlNode *xml_node );

static rule_operator_t *_parse_an_operator( const xmlNode *xml_node ){
	rule_operator_t operator, *ret = NULL;
	xmlAttr *xml_attr;
	const xmlChar *xml_attr_name;
	xmlChar *xml_attr_value;

	//init default values
	operator.value        = OP_TYPE_THEN;
	operator.description  = NULL;
	operator.repeat_times = 1;
	operator.context      = NULL;
	operator.trigger      = NULL;
	operator.delay        = _parse_rule_delay( xml_node );

	//parse attributes of the node
	xml_attr = xml_node->properties;
	while( xml_attr != NULL && xml_attr->name != NULL){
		xml_attr_name  = xml_attr->name;
		xml_attr_value = xmlGetProp( (xmlNodePtr) xml_node, xml_attr_name );

		//for each attribute
		if( str_equal( xml_attr_name, "value" ) ){
			if( str_equal( xml_attr_value, "THEN" ) )
				operator.value = OP_TYPE_THEN;
			else if( str_equal( xml_attr_value, "OR" ) )
				operator.value = OP_TYPE_OR;
			else if( str_equal( xml_attr_value, "AND" ) )
				operator.value = OP_TYPE_AND;
			else if( str_equal( xml_attr_value, "NOT" ) )
				operator.value = OP_TYPE_NOT;
			else
				mmt_assert( 1, "Error 13d: Unexpected attribute value of operator tag: %s", xml_attr_value );
		}else if( str_equal( xml_attr_name, "description" ) )
			operator.description = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		/*
			else
				mmt_log(WARN, "Warning 13e: Unexpected attribute %s in tag operator", xml_attr_name );
		 */
		xmlFree( xml_attr_value );
		xml_attr = xml_attr->next;
	}
	//go inside the node
	xml_node = xml_node->children;
	while( xml_node ){
		if( xml_node->type == XML_ELEMENT_NODE ){
			if( operator.context == NULL )
				operator.context = _parse_a_rule_node( xml_node );
			else if( operator.trigger == NULL )
				operator.trigger = _parse_a_rule_node( xml_node );
			else
				mmt_assert(1, "Error 13f: Unexpected more than 2 children in property tag");
		}

		xml_node = xml_node->next;
	}

	ret = mmt_mem_dup( &operator, sizeof( rule_operator_t ));
	return ret;
}


static rule_node_t *_parse_a_rule_node( const xmlNode *xml_node ){
	rule_node_t *rule_node = mmt_malloc( sizeof( rule_node_t ));
	//init default value
	rule_node->type     = UNKNOWN;
	rule_node->operator = NULL;
	rule_node->event    = NULL;

	if( str_equal( xml_node->name, "operator" ) ){
		rule_node->type     = RULE_OPERATOR;
		rule_node->operator = _parse_an_operator( xml_node );
	}else if( str_equal( xml_node->name, "event" ) ){
		rule_node->type  = RULE_EVENT;
		rule_node->event = _parse_an_event( xml_node );
	}
	else{
		mmt_log(WARN, "Warning 13g: Unexpected tag %s", xml_node->name );
		mmt_free_and_assign_to_null( rule_node );
		rule_node = NULL;
	}
	return rule_node;
}

static rule_t *_parse_a_rule( const xmlNode *xml_node ){
	rule_t rule, *ret = NULL;
	xmlAttr *xml_attr;
	const xmlChar *xml_attr_name;
	xmlChar *xml_attr_value;

	//init default values
	rule.id               = UNKNOWN;
	rule.type             = RULE_TYPE_SECURITY;
	rule.description      = NULL;
	rule.if_satisfied     = NULL;
	rule.if_not_satisfied = NULL;
	rule.keep_state       = NULL;
	rule.context          = NULL;
	rule.trigger          = NULL;
	rule.delay            = _parse_rule_delay( xml_node );

	//parse attributes of the node
	xml_attr = xml_node->properties;
	while( xml_attr != NULL && xml_attr->name != NULL){
		xml_attr_name  = xml_attr->name;
		xml_attr_value = xmlGetProp( (xmlNodePtr) xml_node, xml_attr_name );

		//for each attribute
		if( str_equal( xml_attr_name, "property_id" ) )
			rule.id = (uint8_t) atoi( (const char*) xml_attr_value );
		else if( str_equal( xml_attr_name, "type_property" ) ){
			if( str_equal( xml_attr_value, "ATTACK" ) )
				rule.type = RULE_TYPE_ATTACK;
			else if( str_equal( xml_attr_value, "SECURITY" ) )
				rule.type = RULE_TYPE_SECURITY;
			else if( str_equal( xml_attr_value, "EVASION" ) )
				rule.type = RULE_TYPE_EVASION;
			else if( str_equal( xml_attr_value, "TEST" ) )
				rule.type = RULE_TYPE_TEST;
			else
				mmt_assert( 1, "Error 13c: Unexpected type_property: %s", xml_attr_value );
		}else if( str_equal( xml_attr_name, "description" ) )
			rule.description = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		else if( str_equal( xml_attr_name, "if_satisfied" ) )
			rule.if_satisfied = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		else if( str_equal( xml_attr_name, "if_not_satisfied" ) )
			rule.if_not_satisfied = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		else if( str_equal( xml_attr_name, "keep_state" ) )
			rule.keep_state = mmt_mem_dup( xml_attr_value, strlen( (const char*) xml_attr_value ));
		/*
		else
			mmt_log(WARN, "Warning 13e: Unexpected attribute %s in tag property", xml_attr_name );
		*/
		xmlFree( xml_attr_value );
		xml_attr = xml_attr->next;
	}

	//go inside the node
	xml_node = xml_node->children;
	while( xml_node ){
		if( xml_node->type == XML_ELEMENT_NODE ){
			if( rule.context == NULL )
				rule.context = _parse_a_rule_node( xml_node );
			else if( rule.trigger == NULL )
				rule.trigger = _parse_a_rule_node( xml_node );
			else{
				mmt_assert(1, "Error 13f: Unexpected more than 2 children in property tag");
			}
		}

		xml_node = xml_node->next;
	}
	//TODO: avoid duplicate event_id
	//TODO: avoid variable references to non-exist event

	ret = mmt_mem_dup( &rule, sizeof( rule_t));
	return ret;
}

/**
 * Public API
 */
size_t read_rules_from_file( const char * file_name,  rule_t ***properties_arr){
	xmlDoc *xml_doc = NULL;
	xmlNode *root_node = NULL, *prop_node;
	rule_t *array[1000], **ret ;

	size_t count = 0, i;
	*properties_arr = NULL;

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	//parse the file and get the DOM
	xml_doc = xmlReadFile(file_name, NULL, 0);
	mmt_assert( xml_doc != NULL, "Error 13a: in XML properties file: %s. Parsing failed.\n", file_name );

	/*Get the root element node */
	root_node = xmlDocGetRootElement( xml_doc );

	mmt_assert( root_node->type == XML_ELEMENT_NODE && str_equal(root_node->name, "beginning") ,
			"Error 13b: Name of the root node must be 'beginning', not '%s'", root_node->name );

	//first property
	prop_node = root_node->children;
	while( prop_node != NULL ){

		if( prop_node->type == XML_ELEMENT_NODE && str_equal( prop_node->name, "property") ){
			array[ count ] = _parse_a_rule( prop_node );

			//when we get a new property => increase the counter
			if( array[ count] != NULL )
				count ++;
		}
		//goto the next property
		prop_node = prop_node->next;
	}

	/*free the document */
	xmlFreeDoc( xml_doc );


	//Need to recuperate what attributes will need to be printed out (<proto_id, field_id, data_type_id>)

	// Cleanup function for the XML library.
	xmlCleanupParser();

	//TODO: avoid duplicate rule_id

	//copy result to a new array
	*properties_arr = mmt_mem_dup( &array, count * sizeof( rule_t *) );

	return count;
}

size_t _get_unique_events_of_rule_node( const rule_node_t *node, mmt_map_t *events_map ){
	size_t events_count = 0;
	rule_event_t *ptr;
	if ( node == NULL ) return 0;
	if( node->type == RULE_EVENT ){

		//if user does not set id of event ==> we assign it to an unique number
		if( node->event->id == (uint8_t) UNKNOWN )
			node->event->id = mmt_map_count( events_map ) + 1;

		//check if event is existing in the map
		ptr = mmt_map_set_data( events_map, &(node->event->id), node->event, YES );
		//must not have 2 events with the same id
		mmt_assert( ptr == NULL, "Error 13g: Duplicated events having id=%d", node->event->id );
		return 1;
	}else if( node->type == RULE_OPERATOR ){
		events_count += _get_unique_events_of_rule_node( node->operator->context, events_map );
		events_count += _get_unique_events_of_rule_node( node->operator->trigger, events_map );
		return events_count;
	}else
		mmt_debug( "Unknown rule_node_t->type = %d", node->type );
	return 0;
}

/**
 * Public API
 */
size_t get_unique_events_of_rule( const rule_t *rule, mmt_map_t **events_map ){
	size_t events_count = 0;
	mmt_map_t *map = mmt_map_init( compare_uint8_t );

	events_count += _get_unique_events_of_rule_node( rule->context, map );
	events_count += _get_unique_events_of_rule_node( rule->trigger, map );
	if( events_count == 0 )
		mmt_free_and_assign_to_null( map );
	*events_map = map;
	return events_count;
}
