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
	json_object *json_fs;
	json_object *json_element;
	json_object *json_mounted;
	size_t array_size = 0;

	json_object_object_get_ex(json, parent, &json_fs);

	if (json_object_get_type(json_fs) != json_type_array)
		goto out;

	array_size = json_object_array_length(json_fs);
	if (array_size <= 0)
		goto out;

	for (size_t i = 0; i < array_size; i++) {
		json_element = json_object_array_get_idx(json_fs, i);
		if (!json_element)
			goto out;

		json_object_object_get_ex(json_element, "mounted_on", &json_mounted);
		if (!json_mounted)
			goto out;

		if (strcmp(json_object_get_string(json_mounted), "/") == 0) {
			json_object_object_get_ex(json_element, name, &json_fs);
			if (!json_fs)
				goto out;

			string = json_object_get_string(json_fs);
			break;
		}
	}

out:
	return string;
}
