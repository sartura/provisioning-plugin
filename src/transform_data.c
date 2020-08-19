#include <inttypes.h>
#include <string.h>

#include "transform_data.h"
#include "utils/memory.h"

char *transform_data_key_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	json_object *value;

	json_object_object_get_ex(json, name, &value);
	string = json_object_get_string(value);

	return string ? xstrdup(string) : NULL;
}

char *transform_data_subkey_ubus_transform(json_object *json, const char *parent, const char *name)
{
	const char *string = NULL;
	json_object *value;

	json_object_object_get_ex(json, parent, &value);
	string = json_object_get_string(value);

	json_object_object_get_ex(value, name, &value);
	string = json_object_get_string(value);

	return string ? xstrdup(string) : NULL;
}

char *transform_data_memory_ubus_transform(json_object *json, const char *parent, const char *name)
{
	char string[20 + 1] = {0};
	json_object *json_memory;
	json_object *json_total;
	json_object *json_used;
	uint8_t result = 0;

	json_object_object_get_ex(json, name, &json_memory);
	if (!json_memory)
		goto out;

	json_object_object_get_ex(json_memory, "total", &json_total);
	json_object_object_get_ex(json_memory, "used", &json_used);
	result = (uint8_t)((100 * json_object_get_int(json_used)) / json_object_get_int(json_total));

	snprintf(string, sizeof(string), "%" PRIu8, result);

out:
	return string[0] ? xstrdup(string) : NULL;
}

char *transform_data_disk_ubus_transform(json_object *json, const char *parent, const char *name)
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
		json_object_object_get_ex(json_element, "mounted_on", &json_mounted);

		if (strcmp(json_object_get_string(json_mounted), "/") == 0) {
			json_object_object_get_ex(json_element, name, &json_fs);
			string = json_object_get_string(json_fs);
			break;
		}
	}

out:
	return string ? xstrdup(string) : NULL;
}
