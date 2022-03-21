/*
 * Copyright 2021 (c) Volodymyr "N0dGrand87" Sharaienko <grandamx@gmail.com>
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "mgos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*on_device_control_event_handler)(int isSet, int newState,
                                               void* userData);

enum mgos_app_init_result mgos_app_init(void);

void mgos_wemo_add(const char* device_name,
                   on_device_control_event_handler event_handler,
                   void* userData);

#ifdef __cplusplus
}
#endif