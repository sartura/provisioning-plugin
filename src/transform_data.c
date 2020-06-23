#include <inttypes.h>
#include <string.h>

#include "transform_data.h"
#include "utils/memory.h"

const char *transform_data_key_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	json_object *value;

	if (!name)
		return string;

	json_object_object_get_ex(json, name, &value);
	string = json_object_get_string(value);

	return string;
}

const char *transform_data_subkey_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	json_object *value;

	if (!parent || !name)
		return string;

	json_object_object_get_ex(json, parent, &value);
	string = json_object_get_string(value);

	json_object_object_get_ex(value, name, &value);
	string = json_object_get_string(value);

	return string;
}

const char *transform_data_memory_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	return string;
}

const char *transform_data_disk_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	return string;
}