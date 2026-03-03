# ESPHttpxClient

Lightweight, async HTTP/HTTPS client for ESP32 built on top of esp_tls, with a fully event-driven state machine.

Designed for long-lived connections, chunked transfers and streaming uploads.

## Table of Contents

- [Features](#features)
    - [Why build this instead of using the available clients?](#why-build-this-instead-of-using-the-available-clients)
- [Requirements](#requirements)
- [Architecture Overview](#architecture-overview)
- [Basic Usage Flow](#basic-usage-flow)
- [Configuration](#configuration)
    - [Class Instantiation](#class-instantiation)
- [Sending a Request](#sending-a-request)
    - [Example Skeleton](#example-skeleton)
    - [Sending a Request Body](#sending-a-request-body)
    - [Multipart Form-Data](#multipart-form-data)
- [Additional Options](#additional-options)
    - [Reusing Connection](#reusing-connection)
    - [Connection Mode](#connection-mode)
    - [Set Certificate](#set-certificate)
    - [Set Custom Port](#set-custom-port)
    - [Keep-Alive](#keep-alive)
    - [Redirection Limit](#redirection-limit)
- [Receiving Data](#receiving-data)
- [Events](#events)
- [Error Handling](#error-handling)
- [Important Notes](#important-notes)
- [Design Goals](#design-goals)
- [Full Example](#full-example)
- [Notes](#notes)

## Features

- Plain HTTP and HTTPS support
- TLS with certificate validation (HTTPS_SECURE)
- Fully asynchronous, loop()-driven design
- Chunked transfer encoding (send & receive)
- Multipart form-data (chunked only)
- Automatic HTTP redirection (configurable limit)
- Event-driven interface:
  - Connection events
  - Status line
  - Headers
  - Streaming body data
  - Errors
- Streaming request body via callback
- URL-safe path and query parameter encoding
- Keep-alive or auto-close support

### Why build this instead of using the available clients?

This client was created because I wasn’t able to use the Arduino or ESP-IDF HTTP clients effectively in my particular setup for long-lived connections. So, I built a client designed specifically for my use case.

## Requirements

- ESP32 platform
- esp_tls (should be included out of the box with the Arduino core and ESP-IDF)

## Architecture Overview

`ESPHttpxClient` operates as a state machine driven by:

```cpp
http.start();  // Initiates connection
http.loop();   // Must be called frequently
```

All request construction is event-driven. The client emits events asking you to provide:

- HTTP method
- Hostname
- Path
- Query parameters
- Headers
- Body data (if any)
- You respond by calling the corresponding send*() functions inside the event handler.

Thread Safety: The client should be thread-safe as long as all send*() and start*() calls are made strictly inside the event callbacks or the thread running loop.

## Basic Usage Flow

1. Configure client (mode, keep-alive, certificate, etc.)
2. Register:
   - onEvent() callback
   - onWriteData() callback (if sending body)
3. Call start()
4. Call loop() continuously
5. Handle events

## Configuration

### Class Instantiation

```cpp
ESPHttpxClient http;
// OR
ESPHttpxClient<1024, 1024> http;
```

The class template parameters are:

- First: Size of the data buffer for writing to the request. Default is 512.
- Second: Buffer size for the response headers. This directly refers to the maximum length of a response header that can be parsed.
  - Headers longer than this will be truncated (accounting with both the header name and value).

| Event                         | Description                    |
| ----------------------------- | ------------------------------ |
| `CONNECTION_SUCCESSFUL_EVENT` | TCP/TLS connection established |
| `CONNECTION_FAILED_EVENT`     | Connection attempt failed      |
| `SEND_METHOD_EVENT`           | Provide HTTP method            |
| `SEND_HOSTNAME_EVENT`         | Provide hostname               |
| `SEND_PATH_EVENT`             | Provide request path           |
| `SEND_QUERY_EVENT`            | Provide query parameters       |
| `SEND_USER_HEADERS_EVENT`     | Provide custom headers         |
| `STATUS_RECEIVED_EVENT`       | HTTP status code received      |
| `HEADER_RECEIVED_EVENT`       | Header line received           |
| `DATA_EVENT`                  | Body data received             |
| `REQUEST_FINISHED_EVENT`      | Request fully completed        |
| `DISCONNECTED_EVENT`          | Connection closed              |
| `ERROR_EVENT`                 | Error occurred                 |


## Sending a Request

### Example Skeleton

```cpp

void handleEvent(ESPHttpxClientEvent event, uint8_t* data, size_t len, bool truncated) {
    switch (event) {

        case SEND_HOSTNAME_EVENT:
            http.sendHostname("example.com");
            break;

        case SEND_METHOD_EVENT:
            http.sendHttpMethod(Method::HTTP_GET);
            break;

        case SEND_PATH_EVENT:
            http.sendPath("/api/test");
            break;

        case SEND_QUERY_EVENT:
            http.sendQueryParam("id", 123);
            break;

        case SEND_USER_HEADERS_EVENT:
            http.sendHeader("Custom-Header", "Value");
            http.sendContentHeaders(0); // Required to be called after all other custom headers have been sent
            break;

        case DATA_EVENT:
            Serial.write(data, len);
            break;

        case STATUS_RECEIVED_EVENT:
            // data is a 3-digit status code string (e.g., "200")
            Serial.write(data, len);
            break;

        case REQUEST_FINISHED_EVENT:
            Serial.println("Done.");
            break;

        default:
            break;
    }
}

ESPHttpxClient http;

void setup() {
    http.onEvent(handleEvent);
    http.setMode(HTTPS_SECURE);
    http.setKeepAlive(true);
    http.start();
}

void loop() {
    http.loop();
}
```

### Sending a Request Body

Firstly, you need some data to write:

```cpp
static const char toSend[] = "Lorem ipsum dolor sit amet, reprehenderit nostrud ea cupidatat reprehenderit laborum ipsum sit anim aliqua veniam dolore sunt incididunt nulla deserunt ipsum commodo esse aliqua veniam cillum amet quis qui anim cupidatat eiusmod sed amet laborum voluptate nisi fugiat consequat non sed occaecat velit excepteur aliquip cillum ex elit sed quis mollit et aute esse nostrud et ut proident cillum sit cillum adipiscing quis fugiat et nostrud deserunt fugiat occaecat minim sed anim in proident sunt magna consequat incididunt reprehenderit quis minim qui sed voluptate cupidatat incididunt non non non nisi non anim amet laborum magna est cillum sint consequat officia non amet reprehenderit cupidatat";
static size_t toSendLen = strlen(toSend);
```

- If you know the body length ahead of time, send a fixed Content-Length in the ```SEND_USER_HEADERS_EVENT```:

```cpp
case SEND_USER_HEADERS_EVENT:
    http.sendHeader("Custom-Header", "Value");
    http.sendContentHeaders(128, "application/json"); // Required to be called after all other custom headers have been sent
    break;
```

- If you don't know the body length ahead of time, enable chunked transfer:

```cpp
http.sendContentHeaders(ESP_HTTPX_CONTENT_CHUNKED, "application/json");
```

With this, the client will automatically construct chunks for the body. Useful for when you don't know the size of the body ahead of time.

Then, register a write handler callback to write the data itself:

```cpp
http.onWriteData([](size_t maxLen, size_t index, size_t multipartCounter) {
    if (index >= toSendLen) { // no more data to send
        http.sendBodyData(nullptr, 0); // send a 0 length chunk to end the body
        return;  
    }

    ssize_t toWrite = min(maxLen, (int) toSendLen - (int) index); // you can send chunks of any length up to maxLen
    http.sendBodyData((const uint8_t*) toSend + index, toWrite);
});
```

Note: If sending a fixed content-length, the data sent using the onWriteData callback has to have the exact same length as the value passed here, in total.

### Multipart Form-Data

To send data in a multipart form, firstly enable multipart transfer in the ```SEND_USER_HEADERS_EVENT```:

```cpp
case SEND_USER_HEADERS_EVENT:
    http.sendHeader("Custom-Header", "Value");
    http.sendContentHeaders(ESP_HTTPX_CONTENT_MULTIPART); // Required to be called after all other custom headers have been sent
    break;
```

Note: This client only supports multipart using chunked transfer.

Then you will have to handle the start and end of multipart boundaries in your write handler:

```cpp
static const char toSend[] = "Lorem ipsum dolor sit amet, reprehenderit nostrud ea cupidatat reprehenderit laborum ipsum sit anim aliqua veniam dolore sunt incididunt nulla deserunt ipsum commodo esse aliqua veniam cillum amet quis qui anim cupidatat eiusmod sed amet laborum voluptate nisi fugiat consequat non sed occaecat velit excepteur aliquip cillum ex elit sed quis mollit et aute esse nostrud et ut proident cillum sit cillum adipiscing quis fugiat et nostrud deserunt fugiat occaecat minim sed anim in proident sunt magna consequat incididunt reprehenderit quis minim qui sed voluptate cupidatat incididunt non non non nisi non anim amet laborum magna est cillum sint consequat officia non amet reprehenderit cupidatat";
static size_t toSendLen = strlen(toSend);

static size_t sendTimes = 2;
http.onWriteData([](size_t bufferSize, size_t index, size_t multipartCounter) 
{
    // multipartCounter is the index of the current form element
    // index is the bytes sent for the CURRENT form element
    if (multipartCounter > sendTimes) 
    {
        http.sendBodyData(nullptr, 0); // signal end of entire body
        return;
    }

    if (index == 0) // signals start of every new multipart element
    {
        char nameBuf[64]{};
        snprintf(nameBuf, sizeof(nameBuf), "test-text-%d", multipartCounter);
        http.startMultipartPart("text/plain", nameBuf, "myfile.txt");
    }

    if (index >= toSendLen) // finished current part
    {
        // send true if this is the last element of the form
        http.endMultipart(multipartCounter >= sendTimes); 
        return;
    }

    size_t toWrite = min(bufferSize, toSendLen - index);
    http.sendBodyData((const uint8_t*) toSend + index, toWrite);
});
```

## Additional Options

### Reusing Connection

When keep-alive is enabled:

```cpp
case REQUEST_FINISHED_EVENT:
    http.sendRequest();  // starts another request
    break;
```

The request will restart from the beginning.

### Connection Mode

```cpp
http.setMode(PLAIN_HTTP);      // HTTP only
http.setMode(HTTPS_INSECURE);  // HTTPS without certificate validation
http.setMode(HTTPS_SECURE);    // HTTPS with certificate validation (default) 
```

### Set Certificate

```cpp
http.setCert(certificateBuffer, certificateLength);
```

If no certificate is provided in HTTPS_SECURE mode, the built-in certificate bundle is used.

Note: If using PEM format, the buffer and length must include the null-terminator.

### Set Custom Port

```cpp
http.setPort(8080);
```

Pass -1 or don't call to use the default ports:
- 80 for HTTP
- 443 for HTTPS

### Keep-Alive

```cpp
http.setKeepAlive(true);
```

- true → sends Connection: keep-alive
- false → sends Connection: close

### Redirection Limit

```cpp
http.setMaxRedirections(5);
```

Automatic handling of HTTP 3xx responses via Location header.

## Receiving Data

The client supports:

- Content-Length
- Transfer-Encoding: chunked

Incoming data is delivered incrementally through the ```DATA_EVENT```. No buffering of the entire response is performed internally — data is streamed directly to your handler.

## Events

Register your event handler:

```cpp
void myHandler(ESPHttpxClientEvent event, uint8_t* data, size_t len, bool headerTruncated);
http.onEvent(myHandler);
```

Your handler receives:
- event – the event type (status, headers, data, errors, connection events)
- data – pointer to associated data (header, body chunk, status code, or error code)]
- len – length of data
- headerTruncated – true if a header was truncated due to buffer limits

## Error Handling

Errors trigger the ```ERROR_EVENT```. 

The error code is available in data[0].

Common categories:
- Invalid status line
- Malformed headers
- Invalid chunk format
- Content-length parsing errors
- Write timeout
- Too many redirects

Check the ESPHttpxClientError enum for all the error types.

## Important Notes

- loop() must be called frequently.
- All request building and client request writes must happen inside event callbacks.
- Body data must never exceed the provided max length.
- Multipart requires chunked transfer encoding.
- Redirection between HTTP and HTTPS is restricted depending on mode.
  - Redirection to HTTPs when using PLAIN_HTTP will always fail with an INVALID_REDIRECTION error.
- The client is non-blocking — do not use long delays in event handlers.
- Data passed to ```sendBodyData``` inside the write callback must never exceed the ```bufferSize``` (or ```maxLen```) parameter provided by that specific call.

## Design Goals

- Minimal dynamic allocation
- Predictable memory usage
- Explicit state control
- Works well with long-lived connections and streaming APIs

## Full example

```cpp
#include <Arduino.h>
#include <WiFi.h>

#define ESP_HTTPX_ENABLE_LOGGING // Enable logging for the client
#include <ESPHTTPxClient.h>

using namespace ESP_HTTPX_CLIENT;

ESPHttpxClient http;
unsigned long timer = 0;

// Data to send via chunked upload
const char toSend[] ="Lorem ipsum dolor sit amet, reprehenderit nostrud ea cupidatat reprehenderit laborum ipsum sit anim aliqua veniam dolore sunt incididunt nulla deserunt ipsum commodo esse aliqua veniam cillum amet quis qui anim cupidatat eiusmod sed amet laborum voluptate nisi fugiat consequat non sed occaecat velit excepteur aliquip cillum ex elit sed quis mollit et aute esse nostrud et ut proident cillum sit cillum adipiscing quis fugiat et nostrud deserunt fugiat occaecat minim sed anim in proident sunt magna consequat incididunt reprehenderit quis minim qui sed voluptate cupidatat incididunt non non non nisi non anim amet laborum magna est cillum sint consequat officia non amet reprehenderit cupidatat";
size_t toSendLen = strlen(toSend);
size_t sendTimes = 2;

void setup()
{
    Serial.begin(115200);

    // Connect to Wi-Fi
    WiFi.begin("YOUR WIFI SSID", "YOUR WIFI PASSWORD");
    while (WiFi.status() != WL_CONNECTED)
    {
    }
    WiFi.setSleep(false);
    delay(2000);
    Serial.printf("IP address: %s\n", WiFi.localIP().toString().c_str());

    // Handle body uploads (chunked/multipart)
    http.onWriteData([](size_t bufferSize, size_t index, size_t multipartCounter)
    {
        if (multipartCounter > sendTimes)
        {
            http.sendBodyData(nullptr, 0); 
            return;
        }
    
        if (index == 0)
        {
            char nameBuf[64]{};
            snprintf(nameBuf, sizeof(nameBuf), "test-text-%d", multipartCounter);
            http.startMultipartPart("text/plain", nameBuf);
        }
    
        if (index >= toSendLen) // Removed the 'index > 0' check to allow for empty parts if needed
        {
            http.endMultipart(multipartCounter >= sendTimes);
            return;
        }
    
        size_t toWrite = min(bufferSize, toSendLen - index); // Use bufferSize here!
        http.sendBodyData((const uint8_t*)toSend + index, toWrite);
    });

    static int requestCounter = 0;

    // Event handling
    http.onEvent([](auto event, uint8_t* data, size_t len, bool headerTruncated)
    {
        switch (event)
        {
        case CONNECTION_SUCCESSFUL_EVENT:
            Serial.println("Connection successful");
            break;

        case SEND_HOSTNAME_EVENT:
            http.sendHostname("example.com"); // target host
            break;

        case SEND_METHOD_EVENT:
            http.sendHttpMethod(Method::HTTP_POST);
            break;

        case SEND_PATH_EVENT:
            http.sendPath("/example-path");
            break;

        case SEND_QUERY_EVENT:
            http.sendQueryParam("test", "lorem ipsum long test string...");
            http.sendQueryParam("i", requestCounter);
            break;

        case SEND_USER_HEADERS_EVENT:
            http.sendHeader("x-test", "test");
            http.sendContentHeaders(ESP_HTTPX_CONTENT_MULTIPART);
            break;

        case DATA_EVENT:
            Serial.print("Received data: ");
            Serial.write((char*)data, len);
            Serial.println();
            break;

        case STATUS_RECEIVED_EVENT:
            Serial.print("Received status code: ");
            Serial.write((char*)data, len);
            Serial.println();
            break;

        case HEADER_RECEIVED_EVENT:
            Serial.print("Received header: ");
            Serial.write((char*)data, len);
            Serial.println();
            break;

        case CONNECTION_FAILED_EVENT:
        case DISCONNECTED_EVENT:
            Serial.println("Connection failed/disconnected");
            break;

        case REQUEST_FINISHED_EVENT:
            Serial.println("Request finished");
            requestCounter++;
            if (requestCounter < 3)
            {
                http.sendRequest(); // repeat request
            }
            break;

        case ERROR_EVENT:
            Serial.printf("Error: %d\n", data[0]);
            break;

        default:
            break;
        }
    });

    // Configure client
    http.setMode(HTTPS_SECURE); // HTTPS with certificate validation
    http.setKeepAlive(true);
    http.start();

    Serial.println("HTTP client started");
}

void loop()
{
    http.loop(); // process events and read/write data
}
```

There are some python scripts included in the lib to run a simple HTTP server that logs request logging scripts.

### Notes

- Replace `"SSID"` and `"PASSWORD"` with your Wi-Fi credentials.
- Replace `"example.com"` and `"/example-path"` with your target hostname and path.
- `setKeepAlive(true)` allows reusing the connection for multiple requests.
- `setMode(HTTPS_SECURE)` enables TLS with optional certificate verification; use `PLAIN_HTTP` or `HTTPS_INSECURE` as needed.
- Query parameters added via `sendQueryParam()` are automatically URL-encoded.
- The client handles HTTP redirections and chunked transfer encoding internally.