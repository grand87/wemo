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

#include "mgos_wemo.h"

#include "mgos_mongoose.h"
#include "unpn_server.h"

static UPNPServer wemoDevice;

//// C wrappers for the wemo device API
#ifdef __cplusplus
extern "C" {
#endif

extern void mgos_wemo_add(const char* deviceName,
                          on_device_control_event_handler eventHandler,
                          void* userData) {
    UPNPServer::DeviceInfo newDevice{deviceName, userData, eventHandler};
    wemoDevice.addDevice(newDevice);
}

#ifdef __cplusplus
}
#endif

enum mgos_app_init_result mgos_wemo_init(void) {
    // TODO: add support to read configuration from the YAML file
    wemoDevice.init();
    return MGOS_APP_INIT_SUCCESS;
}
