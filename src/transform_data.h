/**
 * @file transform_data.h
 * @author Jakov Petrina <jakov.petrina@sartura.hr>
 * @brief contains function for transforming
 *
 * @copyright
 * Copyright (C) 2020 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRANSFORM_DATA_H_ONCE
#define TRANSFORM_DATA_H_ONCE

#include <sysrepo.h>
#include <json-c/json.h>

#include <srpo_ubus.h>

char *transform_data_key_ubus_transform(json_object *json, const char *parent, const char *name);
char *transform_data_subkey_ubus_transform(json_object *json, const char *parent, const char *name);
char *transform_data_memory_ubus_transform(json_object *json, const char *parent, const char *name);
char *transform_data_disk_ubus_transform(json_object *json, const char *parent, const char *name);

#endif /* TRANSFORM_DATA_H_ONCE */