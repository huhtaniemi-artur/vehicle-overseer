# device-service-native

Single-header C++17 pinger for Vehicle Overseer. No external dependencies, POSIX sockets only.

## Usage

```cpp
#include "vo_pinger.h"

vo::Pinger pinger("http://10.0.0.1:3100", "AABBCCDDEEFF", "MY_VEHICLE",
                  []() -> std::string { return get_device_address(); });
std::thread t([&]{ pinger.run(); });

// shutdown:
pinger.stop();
t.join();  // clean exit, socket closed
```

## Build

```
g++ -std=c++17 -pthread your_app.cpp -o your_app
```
