//
// Created by xav on 2/23/26.
//

#ifndef ESPHTTPSASYNCLIENT_H
#define ESPHTTPSASYNCLIENT_H

#include <esp_tls.h>
#include <esp_crt_bundle.h>

#define ESP_HTTPX_CLIENT_TIMEOUT (-0x1)

#ifdef ESP_HTTPX_ENABLE_LOGGING
#define ESP_HTTPX_LOG(str) Serial.print(str)
#define ESP_HTTPX_LOGW(str, len) Serial.write(str, len)
#define ESP_HTTPX_LOGN(str) Serial.print("[ESP-HTTPX-CLIENT] "); Serial.println(str)
#define ESP_HTTPX_LOGF(str, p...) Serial.print("[ESP-HTTPX-CLIENT] "); Serial.printf(str, p)
#else
#define ESP_HTTPX_LOG(str)
#define ESP_HTTPX_LOGW(str, len)
#define ESP_HTTPX_LOGN(str)
#define ESP_HTTPX_LOGF(str, p...)
#endif

#define ESP_HTTPX_WRITE_CHECK(data, len, retval, counter)   \
        ssize_t _res##counter = 0;                     \
        do {                                           \
            _res##counter = writeWithTimeout(data, len); \
            ESP_HTTPX_LOGW((const char*) data, len);     \
            if (_res##counter < 0) {                   \
                ESP_HTTPX_LOGF("Write error: 0x%x\n", -(int)_res##counter); \
                return retval;                         \
            }                                          \
        } while(false)

#define ESP_HTTPX_WRITE_CHECK_VOID(data, len, counter)      \
        do {                                           \
            ssize_t _res##counter = writeWithTimeout(data, len); \
            ESP_HTTPX_LOGW((const char*) data, len);     \
            if (_res##counter < 0) {                   \
                ESP_HTTPX_LOGF("Write error: 0x%x\n", -(int)_res##counter); \
                return;                                \
            }                                          \
        } while(false)

#define ESP_HTTPX_WRITE_BOTH(str) ESP_HTTPX_WRITE_CHECK_VOID((const uint8_t*) (str), strlen(str), 0)
#define ESP_HTTPX_WRITE_LN_CHECK_VOID() ESP_HTTPX_WRITE_CHECK_VOID((const uint8_t*) LINE_FEED, LINE_FEED_LEN, 0)

namespace ESP_HTTPX_CLIENT
{
    typedef enum {
        STR2INT_SUCCESS,
        STR2INT_OVERFLOW,
        STR2INT_UNDERFLOW,
        STR2INT_INCONVERTIBLE
    } str2int_errno;

    inline str2int_errno str2ul(unsigned *out, char *s, int base) {
        char *end;
        if (s[0] == '\0' || isspace((unsigned char) s[0]))
            return STR2INT_INCONVERTIBLE;
        errno = 0;
        unsigned long l = strtoul(s, &end, base);
        if (errno == ERANGE && l == ULONG_MAX)
            return STR2INT_OVERFLOW;
        if (*end != '\0')
            return STR2INT_INCONVERTIBLE;
        *out = l;
        return STR2INT_SUCCESS;
    }

    enum Mode
    {
        PLAIN_HTTP,
        HTTPS_SECURE,
        HTTPS_INSECURE, // Only works with the esp-idf, because of pre-compiled code
    };

    enum Method
    {
        HTTP_GET = 0,
        HTTP_POST,
        HTTP_PUT,
        HTTP_DELETE,
    };

    inline const char* methodToString(const Method method)
    {
        switch (method)
        {
            case HTTP_GET: return "GET ";
            case HTTP_POST: return "POST ";
            case HTTP_PUT: return "PUT ";
            case HTTP_DELETE: return "DELETE ";
            default: return nullptr;
        }
    }

    inline bool getHeaderValue(const char *header, size_t len, const char **outStart, size_t *outLen)
    {
        if (header == nullptr || outStart == nullptr || outLen == nullptr || len == 0)
        {
            return false;
        }

        auto start = (const char*) memchr(header, ':', len);
        if (start == nullptr)
        {
            return false;
        }

        start++;
        while (start < (header + len) && isspace((unsigned char) *start))
        {
            start++;
        }

        size_t remaining = len - (start - header);
        if (remaining == 0)
        {
            *outStart = start;
            *outLen = 0;
            return true;
        }

        auto end = (const char*) memchr(start, '\n', remaining);
        if (end == nullptr)
        {
            end = header + len;
        }

        end--;
        while (end > start && isspace((unsigned char) *end))
        {
            end--;
        }

        *outStart = start;
        *outLen = (end - start) + 1;
        return true;
    }


    inline void urlEncode(const char *src, char *dest, size_t dest_size)
    {
        const char *hex = "0123456789ABCDEF";
        size_t i = 0;

        while (*src && i < dest_size - 1)
        {
            unsigned char c = (unsigned char)*src;

            // Unreserved characters (RFC 3986)
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            {
                if (i + 1 >= dest_size) break;
                dest[i++] = c;
            }
            // Space becomes +
            else if (c == ' ')
            {
                if (i + 1 >= dest_size) break;
                dest[i++] = '+';
            }
            // Percent-encode everything else
            else
            {
                if (i + 3 >= dest_size) break;
                dest[i++] = '%';
                dest[i++] = hex[c >> 4];
                dest[i++] = hex[c & 0x0F];
            }

            src++;
        }

        dest[i] = '\0';
    }

    enum ESPHttpxClientState
    {
        STOPPED = 0, // WARNING: Maintain element ordering. State machine depends on this order.
        CONNECTING,
        CONNECTED,
        WRITING_BODY,
        READING_STATUS,
        READING_HEADERS,
        READING_DATA,
        READING_CHUNK_SIZE,
        READING_CHUNK_SIZE_CRLF,
        READING_CHUNK_DATA,
        READING_CHUNK_DATA_CRLF,
    };

    enum ESPHttpxClientEvent
    {
        SEND_HOSTNAME_EVENT,
        CONNECTION_SUCCESSFUL_EVENT,
        CONNECTION_FAILED_EVENT,
        SEND_PATH_AND_QUERY_EVENT,
        ERROR_EVENT,
        STATUS_RECEIVED_EVENT,
        HEADER_RECEIVED_EVENT,
        DATA_EVENT,
        REQUEST_FINISHED_EVENT,
        CONNECTION_CLOSED_EVENT,
    };

    enum ESPHttpxClientError
    {
        MALFORMED_STATUS_LINE = 0,
        MALFORMED_CHUNK_SIZE,
        INVALID_CHUNK_FORMAT,
        WRITE_TIMEOUT,
        TOO_MANY_REDIRECTS,
        INVALID_REDIRECT,
        WRITE_TOO_BIG,
        WRITE_ERROR,
        INVALID_HOSTNAME,
        INVALID_CONTENT_LENGTH,
        INVALID_QUERY_VALUE,
    };

    static const char* HTTP_VER PROGMEM = " HTTP/1.1";
    static const char *CONTENT_LENGTH_HEADER PROGMEM = "Content-Length";

    static const char *TRANSFER_ENCODING_HEADER PROGMEM = "Transfer-Encoding";
    static constexpr size_t TRANSFER_ENCODING_HEADER_LEN = 17;

    static const char *LOCATION_HEADER PROGMEM = "Location";
    static constexpr size_t LOCATION_HEADER_LEN = 8;

    static const char *CHUNKED_HEADER PROGMEM = "chunked";
    static const char *HOST_HEADER PROGMEM = "Host: ";
    static const char *USER_AGENT_HEADER PROGMEM = "User-Agent: ";
    static const char *CONNECTION_KEEP_HEADER PROGMEM = "Connection: keep-alive";
    static const char *CONNECTION_CLOSE_HEADER PROGMEM = "Connection: close";
    static const char *HEADER_SEPARATOR PROGMEM = ": ";
    static const char *REDIRECTION_STATUS PROGMEM = "301";

    static const char *END_CHUNK_MARKER PROGMEM = "0\r\n\r\n";
    static constexpr size_t END_CHUNK_MARKER_LEN = 5;

    static const char *TERMINATORS[] PROGMEM = {"\r\n\r\n", "\n\n"};
    static constexpr size_t TERMINATORS_COUNT = 2;

    static const char LINE_FEED[] PROGMEM = "\r\n";
    static constexpr size_t LINE_FEED_LEN = 2;

    using ESPHttpxClientEventHandler = std::function<void(ESPHttpxClientEvent event, uint8_t *data, size_t len, bool headerTruncated)>;
    using ESPHttpxClientWriteHandler = std::function<ssize_t(uint8_t *buffer, size_t bufferSize, size_t index)>;

    /**
     * Flash size note:
     *
     * Each unique template parameter combination generates a new copy of codethis class. On ESP32 (ESP-IDF, -Os), this
     * typically increases flash usage by ~700 bytes per unique configuration.
     *
     * Avoid creating many different size variations unless necessary.
     *
     * @tparam dataBufferSize    Size of the internal general data buffer.
     * @tparam headerBufferSize  Size of the response header buffer. This determines
     *                           the maximum header line length delivered in the
     *                           HEADER_RECEIVED_EVENT.
     * @tparam maxHostnameLen    Maximum hostname length (including null terminator).
     */
    template <size_t dataBufferSize = 512, size_t headerBufferSize = 256, size_t maxHostnameLen = 128>
    class ESPHttpxClient
    {
        static_assert(dataBufferSize > 0, "dataBufferSize must be > 0");
        static_assert(headerBufferSize > 0, "headerBufferSize must be > 0");
        static_assert(maxHostnameLen > 0, "maxHostnameLen must be > 0");

    public:
        ESPHttpxClient(const ESPHttpxClient&) = delete;
        ESPHttpxClient& operator=(const ESPHttpxClient&) = delete;

        explicit ESPHttpxClient(): dataBuffer{}, currentHeaderBuffer{}
        {
            currentMethod = HTTP_GET;
            keepAlive = false;
            setState(STOPPED);
            eventHandler = nullptr;
            handle = nullptr;
            cert = nullptr;
            certLen = 0;
            config = {};
            headerBufferOffset = 0;
            isReceivingChunked = false;
            currentChunkSize = 0;
            currentChunkOffset = 0;
            port = -1;
            mode = HTTPS_SECURE;
            contentLength = 0;
            contentSentLen = 0;
            hasRedirection = false;
            redirectionCount = 0;
            maxRedirections = 5;
            writeHandler = nullptr;
            currentWriteLen = 0;
            currentWriteOffset = 0;
            receivingContentLength = 0;

            for (size_t i = 0; i < TERMINATORS_COUNT; i++)
            {
                terminatorsLengths[i] = strlen(TERMINATORS[i]);
            }
        }

        ~ESPHttpxClient()
        {
            cleanup();
        }

        void setMaxRedirections(size_t max)
        {
            this->maxRedirections = max;
        }

        /**
         * Certificate for the server. Will use this instead of the global_ca_store.
         * @param cert Certificate buffer. Should include the null terminator if in PEM format.
         * @param len Certificate length. Should include the null terminator if in PEM format.
         */
        void setCert(const char *cert, size_t len)
        {
            this->cert = cert;
            this->certLen = len;
        }

        /**
         * Connection port;
         * @param port desired port or -1 to use default ports
         */
        void setPort(int port)
        {
            this->port = port;
        }

        /**
         * Sets the current client mode.
         * @param mode PLAIN_HTTP, HTTPS_INSECURE or HTTPS_SECURE. Default is HTTPS_SECURE.
         */
        void setMode(Mode mode)
        {
            this->mode = mode;
        }

        /**
         * Starts the HTTP request. Set the envent handler with onEvent before calling this.
         */
        void start()
        {
            if (isTlsStarted())
            {
                ESP_HTTPX_LOGN("Tried to connect but connection already started.");
                return;
            }

            handle = esp_tls_init();
            // memset(&config, 0, sizeof(config));

            config = {
                .cacert_buf = mode == PLAIN_HTTP || mode == HTTPS_INSECURE ? nullptr : (const unsigned char*)cert,
                .cacert_bytes = mode == PLAIN_HTTP || mode == HTTPS_INSECURE ? 0 : certLen,
                .non_block = true,
                .skip_common_name = mode == PLAIN_HTTP || mode == HTTPS_INSECURE,
                .is_plain_tcp = mode == PLAIN_HTTP,
            };

            if (mode == HTTPS_SECURE && (cert == nullptr || certLen == 0))
            {
                config.crt_bundle_attach = esp_crt_bundle_attach;
            }

            setState(CONNECTING);
        }

        /**
         * Sends a HTTP header. Call in the CONNECTION_SUCCESSFUL_EVENT callback passed to onEvent.
         *
         * @param name header name
         * @param value header value
         */
        void sendHeader(const char *name, const char *value)
        {
            ESP_HTTPX_WRITE_BOTH(name);
            ESP_HTTPX_WRITE_BOTH(HEADER_SEPARATOR);
            ESP_HTTPX_WRITE_BOTH(value);
            ESP_HTTPX_WRITE_LN_CHECK_VOID();
        }

        /**
         * Sends the request Content-Length header. Should always be called after all other desired headers have been sent.
         * @param length Length of the content to be sent. Set to less than 0 to use chunked transfer.
         */
        void sendContentLength(ssize_t length)
        {
            contentLength = length;

            if (length >= 0)
            {
                char numBuf[32]{};
                snprintf(numBuf, sizeof(numBuf), "%lu", length);
                sendHeader(CONTENT_LENGTH_HEADER, numBuf);

                if (length == 0)
                {
                    setState(READING_STATUS);
                }
            }
            else
            {
                sendHeader(TRANSFER_ENCODING_HEADER, CHUNKED_HEADER);
            }

            ESP_HTTPX_WRITE_LN_CHECK_VOID();
        }

        bool isSendingChunked() const
        {
            return contentLength < 0;
        }

        void startWrite()
        {
            setState(WRITING_BODY);
        }

        /**
         * Must be called to end the writing of the body, if using chunked transfer (content-length < 0).
         */
        void endChunkedBody()
        {
            if (isSendingChunked())
            {
                ESP_HTTPX_WRITE_CHECK_VOID(END_CHUNK_MARKER, END_CHUNK_MARKER_LEN, 0);
                setState(READING_STATUS);
            }
        }

        /**
         * Stop request and close connection.
         */
        void close()
        {
            cleanup();
        }

        void loop()
        {
            if (handle != nullptr && currentState == CONNECTING)
            {
                callCb(SEND_HOSTNAME_EVENT);
            }

            if (handle != nullptr && currentState == WRITING_BODY)
            {
                if (writeHandler == nullptr)
                {
                    setState(READING_STATUS);
                    return;
                }

                if (currentWriteOffset >= currentWriteLen)
                {
                    static constexpr size_t chunkHeaderMaxLen = 30;

                    uint8_t *actualBuffer = isSendingChunked() ? dataBuffer + chunkHeaderMaxLen : dataBuffer; // reserve space for chunk size and crlf
                    size_t actualBufferLen = isSendingChunked() ? dataBufferSize-chunkHeaderMaxLen-2 : dataBufferSize; // reserve space for chunk end crlf

                    currentWriteLen = writeHandler(actualBuffer, actualBufferLen, currentWriteTotal);
                    currentWriteTotal += currentWriteLen;
                    currentWriteOffset = 0;

                    if (currentWriteLen > actualBufferLen)
                    {
                        ESP_HTTPX_LOGN("Body data buffer overflow.");
                        callError(WRITE_TOO_BIG);
                        return;
                    }

                    if (isSendingChunked() && currentWriteLen > 0)
                    {
                        char chunkSizeBuf[chunkHeaderMaxLen + 1]{};
                        snprintf(chunkSizeBuf, sizeof(chunkSizeBuf), "%x\r\n", currentWriteLen);
                        size_t chunkSizeLen = strlen(chunkSizeBuf);
                        if (chunkSizeLen > chunkHeaderMaxLen)
                        {
                            ESP_HTTPX_LOGN("Chunk header buffer overflow.");
                            callError(WRITE_TOO_BIG);
                            return;
                        }

                        uint8_t *headerStart = actualBuffer-chunkSizeLen;
                        memcpy(headerStart, chunkSizeBuf, chunkSizeLen);

                        actualBuffer[currentWriteLen] = '\r';
                        actualBuffer[currentWriteLen+1] = '\n';

                        currentWriteLen += chunkSizeLen + 2;
                        memmove(dataBuffer, headerStart, currentWriteLen);
                    }

                    if (currentWriteLen <= 0)
                    {
                        if (isSendingChunked())
                        {
                            sendingZeroChunk = true;
                            memcpy(dataBuffer, "0\r\n\r\n", 5);
                            currentWriteLen = 5;
                            currentWriteOffset = 0;
                            return;
                        }

                        setState(READING_STATUS);
                        ESP_HTTPX_LOG('\n');
                    }
                }
                else
                {
                    ssize_t written = esp_tls_conn_write(handle, dataBuffer + currentWriteOffset, currentWriteLen - currentWriteOffset); // TODO handle 0 writes
                    ESP_HTTPX_LOGW(dataBuffer + currentWriteOffset, currentWriteLen - currentWriteOffset);

                    if (hasWriteError(written))
                    {
                        ESP_HTTPX_LOGF("Error writing to body: 0x%x\n", written);
                        callError(WRITE_ERROR);
                        return;
                    }

                    currentWriteOffset += written;
                    if (isSendingChunked() && sendingZeroChunk && currentWriteOffset >= currentWriteLen)
                    {
                        setState(READING_STATUS);
                        ESP_HTTPX_LOG('\n');
                    }
                }
            }
            else if (currentState > WRITING_BODY)
            {
                ssize_t read = esp_tls_conn_read(handle, dataBuffer, dataBufferSize);
                if (read == -0x004C) // Reading information from the socket failed
                {
                    ESP_HTTPX_LOGN("Connection has been closed forcefully.");
                    callCb(CONNECTION_CLOSED_EVENT);
                    return;
                }

                if (read == -0x50)
                {
                    ESP_HTTPX_LOGN("Connection reset by peer.");
                    callCb(CONNECTION_CLOSED_EVENT);
                    return;
                }

                if (read < 0 && read != -0x6900 && (mode != PLAIN_HTTP || read != ESP_HTTPX_CLIENT_TIMEOUT)) // No data of requested type currently available on underlying transport
                {
                    ESP_HTTPX_LOGF("Error reading data from socket: 0x%x\n", -read);
                    return;
                }

                if (read <= 0)
                {
                    return;
                }

                size_t start = 0;
                while (start < read)
                {
                    size_t remaining = read - start;
                    uint8_t *startBuffer = dataBuffer + start;

                    switch (currentState)
                    {
                    case READING_STATUS:
                        {
                            if (headerBufferOffset >= headerBufferSize - 1)
                            {
                                ESP_HTTPX_LOGN("Error parsing status line.");
                                callError(MALFORMED_STATUS_LINE);
                                return;
                            }

                            bool foundNewline = false;
                            for (size_t i = 0; i < remaining; i++)
                            {
                                if (startBuffer[i] == '\n')
                                {
                                    if (headerBufferOffset > headerBufferSize)
                                    {
                                        headerBufferOffset = headerBufferSize;
                                    }

                                    if (headerBufferOffset < 2)
                                    {
                                        ESP_HTTPX_LOGN("Error parsing status line.");
                                        callError(MALFORMED_STATUS_LINE);
                                        return;
                                    }

                                    size_t nullPos = currentHeaderBuffer[headerBufferOffset-2] == '\r' ? headerBufferOffset-2 : headerBufferOffset-1;
                                    if (nullPos >= headerBufferSize) // underflow protection
                                    {
                                        ESP_HTTPX_LOGN("Error parsing status line.");
                                        callError(MALFORMED_STATUS_LINE);
                                        return;
                                    }

                                    currentHeaderBuffer[nullPos] = 0;
                                    start++;
                                    foundNewline = true;
                                    break;
                                }

                                if (headerBufferOffset >= headerBufferSize)
                                {
                                    ESP_HTTPX_LOGN("Error parsing status line.");
                                    callError(MALFORMED_STATUS_LINE);
                                    return;
                                }

                                currentHeaderBuffer[headerBufferOffset] = startBuffer[i];
                                headerBufferOffset++;
                                start++;
                            }

                            if (!foundNewline)
                            {
                                continue;
                            }

                            if (strncmp(currentHeaderBuffer, "HTTP/", 5) != 0)
                            {
                                ESP_HTTPX_LOGN("Malformed status line.");
                                callError(MALFORMED_STATUS_LINE);
                                return;
                            }

                            size_t statusLen = strlen(currentHeaderBuffer);
                            char *firstSpace = (char*) memchr(currentHeaderBuffer, ' ', statusLen);
                            if (firstSpace == nullptr ||
                                statusLen - (firstSpace - currentHeaderBuffer) < 4 ||
                                !isdigit((unsigned char) firstSpace[1]) ||
                                !isdigit((unsigned char) firstSpace[2]) ||
                                !isdigit((unsigned char) firstSpace[3]))
                            {
                                ESP_HTTPX_LOGN("Malformed status line.");
                                callError(MALFORMED_STATUS_LINE);
                                return;
                            }

                            if (strncmp(firstSpace+1, "100", 3) == 0)
                            {
                                setState(READING_STATUS);
                                continue;
                            }

                            callCb(STATUS_RECEIVED_EVENT, (uint8_t*) (firstSpace+1), 3);
                            setState(READING_HEADERS);
                            continue;
                        }
                    case READING_HEADERS:
                        {
                            if (currentHeaderBuffer[0] == 0)
                            {
                                headerBufferOffset = 0;
                            }

                            bool cont = false;
                            for (size_t i = start; i < read; i++)
                            {
                                bool terminatorFound = false;
                                char c = dataBuffer[i];

                                for (size_t j = 0; j < TERMINATORS_COUNT; j++)
                                {
                                    if (TERMINATORS[j][terminatorMatchCounts[j]] == c)
                                    {
                                        terminatorMatchCounts[j]++;
                                    }
                                    else
                                    {
                                        terminatorMatchCounts[j] = (TERMINATORS[j][0] == c) ? 1 : 0;
                                    }

                                    if (terminatorMatchCounts[j] >= terminatorsLengths[j])
                                    {
                                        terminatorFound = true;
                                        break;
                                    }
                                }

                                if (terminatorFound)
                                {
                                    if (isReceivingChunked)
                                    {
                                        setState(READING_CHUNK_SIZE);
                                    }
                                    else
                                    {
                                        setState(READING_DATA);
                                    }

                                    start = i + 1;
                                    cont = true;
                                    break;
                                }

                                if (headerBufferOffset >= headerBufferSize - 1)
                                {
                                    currentHeaderBuffer[headerBufferSize - 1] = 0;
                                    callCb(HEADER_RECEIVED_EVENT, (uint8_t*)currentHeaderBuffer, headerBufferSize - 1, true);
                                    headerBufferOffset = 0;

                                    if (hasRedirection && redirectionProcessed)
                                    {
                                        ESP_HTTPX_LOGN("Received header is location with redirection status, aborting header parsing.");
                                        return;
                                    }
                                }

                                currentHeaderBuffer[headerBufferOffset++] = c;

                                if (c == '\n')
                                {
                                    size_t lineLength = headerBufferOffset;

                                    if (lineLength >= 2 && currentHeaderBuffer[lineLength - 2] == '\r')
                                    {
                                        lineLength -= 2;
                                    }
                                    else
                                    {
                                        lineLength -= 1;
                                    }

                                    currentHeaderBuffer[lineLength] = 0;
                                    if (lineLength > 0)
                                    {
                                        callCb(HEADER_RECEIVED_EVENT, (uint8_t*) currentHeaderBuffer, lineLength);

                                        if (hasRedirection && redirectionProcessed)
                                        {
                                            ESP_HTTPX_LOGN("Received header is location with redirection status, aborting header parsing.");
                                            return;
                                        }
                                    }

                                    headerBufferOffset = 0;
                                    currentHeaderBuffer[0] = 0;
                                }
                            }

                            if (cont)
                            {
                                continue;
                            }

                            start = read;
                            break;
                        }
                    case READING_DATA:
                        {
                            ESP_HTTPX_LOGF("Read %lu bytes from the socket\n", remaining);
                            callCb(DATA_EVENT, (uint8_t*) dataBuffer + start, remaining);
                            start = read;

                            currentChunkOffset += read;
                            if (currentChunkOffset >= receivingContentLength)
                            {
                                callCb(REQUEST_FINISHED_EVENT);
                            }
                            continue;
                        }
                    case READING_CHUNK_SIZE:
                        {
                            bool cont = false;
                            uint8_t *offsetBuffer = dataBuffer + start;
                            for (size_t i = 0; i < remaining; i++)
                            {
                                if (currentChunkOffset >= sizeof(chunkSizeBuf)-1)
                                {
                                    ESP_HTTPX_LOGN("Could not parse chunk size.");
                                    callError(MALFORMED_CHUNK_SIZE);
                                    return;
                                }

                                if (offsetBuffer[i] == '\n')
                                {
                                    size_t nullPos = chunkSizeBuf[currentChunkOffset-1] == '\r' ? currentChunkOffset-1 : currentChunkOffset;
                                    chunkSizeBuf[nullPos] = 0;
                                    setState(READING_CHUNK_SIZE_CRLF);
                                    start += i;
                                    cont = true;
                                    break;
                                }

                                chunkSizeBuf[currentChunkOffset] = offsetBuffer[i];
                                currentChunkOffset++;
                            }

                            if (cont)
                            {
                                continue;
                            }
                            break;
                        }
                    case READING_CHUNK_SIZE_CRLF:
                        {
                            char c = (dataBuffer + start)[0];
                            if (c != '\n')
                            {
                                ESP_HTTPX_LOGN("Error parsing chunk header, invalid line ending.");
                                callError(MALFORMED_CHUNK_SIZE);
                                return;
                            }

                            int res = str2ul(&currentChunkSize, chunkSizeBuf, 16);
                            if (res != STR2INT_SUCCESS)
                            {
                                ESP_HTTPX_LOGF("Error parsing chunk size: %d\n", res);
                                callError(MALFORMED_CHUNK_SIZE);
                                return;
                            }

                            ESP_HTTPX_LOGF("Current chunk size is %zu\n", currentChunkSize);
                            if (currentChunkSize == 0)
                            {
                                callCb(REQUEST_FINISHED_EVENT);
                                return;
                            }

                            setState(READING_CHUNK_DATA);
                            start++;
                            break;
                        }
                    case READING_CHUNK_DATA:
                        {
                            size_t chunkRemaining = currentChunkSize - currentChunkOffset;

                            size_t toConsume = (remaining < chunkRemaining) ? remaining : chunkRemaining;
                            callCb(DATA_EVENT, dataBuffer + start, toConsume);

                            currentChunkOffset += toConsume;
                            start += toConsume;

                            if (currentChunkOffset == currentChunkSize)
                            {
                                setState(READING_CHUNK_DATA_CRLF);
                            }
                            break;
                        }
                    case READING_CHUNK_DATA_CRLF:
                        {
                            size_t available = remaining;
                            if (available == 0)
                            {
                                continue;
                            }

                            char c = dataBuffer[start];
                            if (c == '\r')
                            {
                                start++;
                                if (start >= read)
                                {
                                    continue;
                                }

                                if (dataBuffer[start] != '\n')
                                {
                                    ESP_HTTPX_LOGN("Invalid chunk terminator (CR not followed by LF).");
                                    callError(INVALID_CHUNK_FORMAT);
                                    return;
                                }

                                start++;
                                setState(READING_CHUNK_SIZE);
                                continue;
                            }

                            if (c == '\n')
                            {
                                start++;
                                setState(READING_CHUNK_SIZE);
                                continue;
                            }

                            ESP_HTTPX_LOGN("Invalid chunk terminator (expected CRLF or LF).");
                            callError(INVALID_CHUNK_FORMAT);
                            return;
                        }
                    default: ;
                    }
                }
            }
        }

        void sendHostname(const char *hostname)
        {
            sendHostname(hostname, strlen(hostname));
        }

        void sendHostname(const char *hostname, size_t len)
        {
            if (hostname == nullptr || len == 0)
            {
                ESP_HTTPX_LOGN("Invalid hostname");
                callError(INVALID_HOSTNAME);
                return;
            }

            if (currentState == CONNECTING)
            {
                int actualPort = port <= 0 ? (mode == PLAIN_HTTP ? 80 : 443) : port;
                int res = esp_tls_conn_new_async(hostname, len, actualPort, &config, handle);

                if (res == 1)
                {
                    ESP_HTTPX_LOGN("Connected succesfully.");
                    callCb(CONNECTION_SUCCESSFUL_EVENT);
                }
                else if (res == -1)
                {
                    ESP_HTTPX_LOGN("Connection failed.");
                    callCb(CONNECTION_FAILED_EVENT);
                }
            }
            else
            {
                ESP_HTTPX_WRITE_CHECK_VOID(hostname, len, 0);
            }
        }

        void setKeepAlive(bool keepAlive)
        {
            this->keepAlive = keepAlive;
        }

        void sendPath(const char *path)
        {
            if (path == nullptr || path[0] == 0)
            {
                writeUrlEncoded("/", false);
                return;
            }

            if (path[0] != '/')
            {
                writeUrlEncoded("/", false);
            }

            writeUrlEncoded(path, false);
        }

        void sendQueryParam(const char *name, long long value)
        {
            char numBuf[32]{};
            int w = snprintf(numBuf, sizeof(numBuf), "%lld", value);
            if (w >= sizeof(numBuf))
            {
                ESP_HTTPX_LOGN("Number is too big for the query value, send as string directly.");
                callError(INVALID_CHUNK_FORMAT);
                return;
            }

            sendQueryParam(name, numBuf);
        }

        void sendQueryParam(const char *name, const char *value)
        {
            ESP_HTTPX_WRITE_CHECK_VOID(sentFirstQueryParam ? "&" : "?", 1, 0);
            writeUrlEncoded(name);
            ESP_HTTPX_WRITE_CHECK_VOID("=", 1, 0);
            writeUrlEncoded(value);
            sentFirstQueryParam = true;
        }

        bool writeUrlEncoded(const char *src, bool uriComponentEncoding = true, unsigned long timeout = 2500)
        {
            constexpr char hex[] = "0123456789ABCDEF";

            uint8_t buffer[64];
            size_t pos = 0;

            auto flush = [&](void) -> bool
            {
                if (pos == 0) return true;
                ESP_HTTPX_WRITE_CHECK(buffer, pos, false, 0);
                pos = 0;
                return true;
            };

            while (*src)
            {
                unsigned char c = (unsigned char)*src;

                if (pos + 3 > sizeof(buffer))
                {
                    if (!flush()) return false;
                }

                if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || (!uriComponentEncoding && c == '/'))
                {
                    buffer[pos++] = c;
                }
                else if (c == ' ' && uriComponentEncoding)
                {
                    buffer[pos++] = '+';
                }
                else
                {
                    buffer[pos++] = '%';
                    buffer[pos++] = hex[c >> 4];
                    buffer[pos++] = hex[c & 0x0F];
                }

                src++;
            }

            return flush();
        }

        void sendRequest()
        {
            callCb(CONNECTION_SUCCESSFUL_EVENT);
        }

        /**
         * Register callback for client events.
         */
        void onEvent(ESPHttpxClientEventHandler cb)
        {
            eventHandler = cb;
        }

        void onWriteData(ESPHttpxClientWriteHandler cb)
        {
            this->writeHandler = cb;
        }
    private:

        void setState(ESPHttpxClientState newState)
        {
            currentState = newState;

            switch (newState)
            {
            case STOPPED:
                {
                    break;
                }
            case CONNECTING:
                {
                    sentFirstQueryParam = false;
                    break;
                }
            case CONNECTED:
                {
                    sentFirstQueryParam = false;
                    break;
                }
            case READING_DATA:
                {
                    redirectionCount = 0;
                    break;
                }
            case WRITING_BODY:
                {
                    memset(dataBuffer, 0, dataBufferSize);
                    hasRedirection = false;
                    redirectionProcessed = false;
                    currentWriteTotal = 0;
                    currentWriteOffset = 0;
                    currentWriteLen = 0;
                    sendingZeroChunk = false;
                    break;
                }
            case READING_STATUS:
            case READING_HEADERS:
                {
                    headerBufferOffset = 0;
                    memset(currentHeaderBuffer, 0, headerBufferSize);
                    memset(terminatorMatchCounts, 0, sizeof(terminatorMatchCounts));
                    break;
                }
            case READING_CHUNK_DATA:
            case READING_CHUNK_SIZE:
            case READING_CHUNK_DATA_CRLF:
                {
                    redirectionCount = 0;
                    currentChunkOffset = 0;
                    break;
                }
            case READING_CHUNK_SIZE_CRLF:
                {
                    break;
                }
            }
        }

        void writeHttpLine(const char *userAgent = "ESP32-HTTPX-CLIENT")
        {
            const char *methodStr = methodToString(currentMethod);
            if (methodStr == nullptr)
            {
                return;
            }

            ESP_HTTPX_LOGN("Sending request line.");

            ESP_HTTPX_WRITE_BOTH(methodStr);
            callCb(SEND_PATH_AND_QUERY_EVENT);
            ESP_HTTPX_WRITE_BOTH(HTTP_VER);
            ESP_HTTPX_WRITE_LN_CHECK_VOID();

            ESP_HTTPX_WRITE_BOTH(HOST_HEADER);
            callCb(SEND_HOSTNAME_EVENT);
            ESP_HTTPX_WRITE_LN_CHECK_VOID();

            ESP_HTTPX_WRITE_BOTH(USER_AGENT_HEADER);
            ESP_HTTPX_WRITE_BOTH(userAgent);
            ESP_HTTPX_WRITE_LN_CHECK_VOID();

            ESP_HTTPX_WRITE_BOTH(keepAlive ? CONNECTION_KEEP_HEADER : CONNECTION_CLOSE_HEADER);
            ESP_HTTPX_WRITE_LN_CHECK_VOID();
        }

        ssize_t writeWithTimeout(const char *data, size_t len, unsigned long timeout = 2500)
        {
            return writeWithTimeout((const uint8_t*) data, len, timeout);
        }

        bool hasWriteError(ssize_t result) const
        {
            return result < 0 &&
                result != ESP_TLS_ERR_SSL_WANT_READ &&
                result != ESP_TLS_ERR_SSL_WANT_WRITE &&
                (mode != PLAIN_HTTP || result != ESP_HTTPX_CLIENT_TIMEOUT);
        }

        ssize_t writeWithTimeout(const uint8_t *data, size_t len, unsigned long timeout = 2500)
        {
            unsigned long timer = millis();
            ssize_t remaining = len;

            while (remaining > 0)
            {
                if (millis() - timer > timeout)
                {
                    break;
                }

                ssize_t sent = esp_tls_conn_write(handle, data + len - remaining, remaining);
                if (sent > 0)
                {
                    remaining -= sent;
                    timer = millis();
                }
                else if (hasWriteError(sent))
                {
                    ESP_HTTPX_LOGF("Error writing to socket: 0x%x\n", -sent);
                    return sent;
                }

                vTaskDelay(1);
            }

            if (remaining > 0)
            {
                callError(WRITE_TIMEOUT);
                return ESP_HTTPX_CLIENT_TIMEOUT;
            }

            return len;
        }

        void handleRedirection(const char *locationHeader, size_t headerLen)
        {
            if (redirectionCount >= maxRedirections)
            {
                ESP_HTTPX_LOGN("HTTP redirections exceeded the limit.");
                callError(TOO_MANY_REDIRECTS);
                return;
            }

            const char *valueStart = nullptr;
            size_t valueLen = 0;
            bool found = getHeaderValue(locationHeader, headerLen, &valueStart, &valueLen);
            if (!found)
            {
                callError(INVALID_REDIRECT);
                return;
            }

            if (mode == PLAIN_HTTP && valueLen >= 5 && strncasecmp(valueStart, "https", 5) == 0)
            {
                ESP_HTTPX_LOGN("Unsupported HTTPS redirect, aborting.");
                callError(INVALID_REDIRECT);
                return;
            }

            const char *pathStart = valueStart;
            size_t pathLen = valueLen;

            const char *protocolSeparator = strnstr(valueStart, "://", valueLen);
            const char *hostStart = nullptr;
            size_t hostLength = 0;
            if (protocolSeparator != nullptr)
            {
                size_t protoLen = protocolSeparator - valueStart;
                if (protoLen < 3) {
                    ESP_HTTPX_LOGN("Invalid protocol separator position.");
                    callError(INVALID_REDIRECT);
                    return;
                }

                size_t lenWithoutProtocol = valueLen - protoLen - 3;
                if (strncasecmp(valueStart, "http", 4) != 0 && strncasecmp(valueStart, "https", 5) != 0)
                {
                    ESP_HTTPX_LOGN("Unsupported redirect protocol.");
                    callError(INVALID_REDIRECT);
                    return;
                }

                hostStart = protocolSeparator+3;
                const char *hostEnd = (const char*) memchr(hostStart, ':', lenWithoutProtocol);
                if (hostEnd == nullptr)
                {
                    hostEnd = (const char*) memchr(hostStart, '/', lenWithoutProtocol);
                }
                else
                {
                    char portBuf[10]{};
                    const char *portStart = hostEnd + 1;
                    size_t portOffset = portStart - valueStart;
                    if (portOffset > valueLen) {
                        ESP_HTTPX_LOGN("Port offset exceeds header length.");
                        callError(INVALID_REDIRECT);
                        return;
                    }

                    size_t portLen = valueLen - portOffset;
                    portLen = min(sizeof(portBuf)-1, portLen);
                    memcpy(portBuf, portStart, portLen);
                    portBuf[portLen] = 0;

                    unsigned int parsedPort = 0;
                    int res = str2ul(&parsedPort, portBuf, 10);
                    if (res != STR2INT_SUCCESS)
                    {
                        ESP_HTTPX_LOGF("Error converting redirect port: %d\n", res);
                        callError(INVALID_REDIRECT);
                        return;
                    }

                    ESP_HTTPX_LOGF("New port: %d\n", parsedPort);
                    setPort(parsedPort);
                }

                hostLength = hostEnd ? (hostEnd - hostStart) : lenWithoutProtocol;
                if (hostLength <= 0 || (size_t)hostLength > maxHostnameLen) {
                    ESP_HTTPX_LOGN("Invalid host length.");
                    callError(INVALID_REDIRECT);
                    return;
                }

                ESP_HTTPX_LOG("New hostname: ");
                ESP_HTTPX_LOGW(hostStart, hostLength);
                ESP_HTTPX_LOG("\n");

                pathStart = (const char*) memchr(hostStart, '/', lenWithoutProtocol);
                if (pathStart != nullptr)
                {
                    pathLen = lenWithoutProtocol - (pathStart - hostStart);
                    ESP_HTTPX_LOG("New path: ");
                    ESP_HTTPX_LOGW(pathStart, pathLen);
                    ESP_HTTPX_LOG('\n');
                }
            }

            redirectionProcessed = true;
            redirectionCount++;

            ESPHttpxClientEventHandler oldHandler = eventHandler;
            onEvent([this, oldHandler, pathStart, pathLen, hostStart, hostLength](ESPHttpxClientEvent event, uint8_t* data, size_t len, bool headerTruncated)
            {
                // WARNING:
                // Path and host string are only valid here because they point to the currentHeaderBuffer class variable.
                // If it was a dynamic buffer this would not work.

                if (event == SEND_HOSTNAME_EVENT && (hostStart == nullptr || hostLength <= 0))
                {
                    oldHandler(event, data, len, headerTruncated); // call original event if location has no host
                }
                else if (event == SEND_HOSTNAME_EVENT)
                {
                    sendHostname(hostStart, hostLength);
                }
                else if (event == SEND_PATH_AND_QUERY_EVENT)
                {
                    const char *path = pathStart == nullptr ? "/" : pathStart;
                    const size_t finalPathLen = pathStart == nullptr ? 1 : pathLen;
                    writeWithTimeout(path, finalPathLen);
                    ESP_HTTPX_LOGW(path, finalPathLen);
                }
                else
                {
                    oldHandler(event, data, len, headerTruncated);
                    this->eventHandler = oldHandler;
                }
            });

            cleanup();
            start();
        }

        void parseContentLength(const char *header, size_t len)
        {
            const char *valueStart = nullptr;
            size_t valueLen = 0;

            bool found = getHeaderValue(header, len, &valueStart, &valueLen);
            if (!found || valueStart == nullptr || valueLen == 0)
            {
                ESP_HTTPX_LOGN("Could not parse content-length header.");
                callError(INVALID_CONTENT_LENGTH);
                return;
            }

            char valueBuffer[32]{};
            size_t valueBufferLen = min(valueLen, sizeof(valueBuffer)-1);
            memcpy(valueBuffer, valueStart, valueBufferLen);
            valueBuffer[valueBufferLen] = 0;

            int parseRes = str2ul(&receivingContentLength, valueBuffer, 10);
            if (parseRes != STR2INT_SUCCESS)
            {
                ESP_HTTPX_LOGF("Error parsing content-length: %d\n", parseRes);
                callError(INVALID_CONTENT_LENGTH);
                receivingContentLength = 0;
                return;
            }

            ESP_HTTPX_LOGF("Parsed content-length: %lu\n", receivingContentLength);
        }

        void callError(ESPHttpxClientError error)
        {
            uint8_t data[] = {(uint8_t) error};
            callCb(ERROR_EVENT, data, 1);
        }

        void callCb(const ESPHttpxClientEvent event, uint8_t *data = nullptr, size_t len = 0, bool truncated = false)
        {
            if (event == CONNECTION_SUCCESSFUL_EVENT)
            {
                setState(CONNECTED);
                writeHttpLine();
            }
            else if (event == CONNECTION_FAILED_EVENT || event == CONNECTION_CLOSED_EVENT || event == ERROR_EVENT)
            {
                if (hasRedirection)
                {
                    redirectionProcessed = true;
                }
                cleanup();
            }
            else if (event == STATUS_RECEIVED_EVENT && data != nullptr && len >= 3 && memcmp(data, REDIRECTION_STATUS, 3) == 0)
            {
                ESP_HTTPX_LOGN("Redirection detected.");
                hasRedirection = true;
            }
            else if (event == HEADER_RECEIVED_EVENT && data != nullptr && len > 0)
            {
                if (len >= TRANSFER_ENCODING_HEADER_LEN && strncasecmp((char*) data, TRANSFER_ENCODING_HEADER, TRANSFER_ENCODING_HEADER_LEN) == 0)
                {
                    isReceivingChunked = true;
                }
                else if (len >= 14 && strncasecmp((char*) data, "Content-Length", 14) == 0) // TODO make constant
                {
                    parseContentLength((char*) data, len);
                }

                if (hasRedirection && len >= LOCATION_HEADER_LEN && strncasecmp((char*) data, LOCATION_HEADER, LOCATION_HEADER_LEN) == 0)
                {
                    handleRedirection((const char*) data, len);
                    return;
                }

                if (isReceivingChunked && receivingContentLength > 0)
                {
                    ESP_HTTPX_LOGN("Received chunked transfer encoding and content-length in the same request.");
                    callError(INVALID_CONTENT_LENGTH);
                    return;
                }
            }

            if (eventHandler)
            {
                eventHandler(event, data, len, truncated);
            }
        }

        void cleanup()
        {
            if (handle != nullptr)
            {
                esp_tls_conn_destroy(handle);
                handle = nullptr;
            }

            currentState = STOPPED;
            headerBufferOffset = 0;
            currentChunkSize = 0;
            currentChunkOffset = 0;
            contentSentLen = 0;
            contentLength = 0;
            isReceivingChunked = false;
            currentWriteLen = 0;
            currentWriteOffset = 0;
            currentWriteTotal = 0;
            sendingZeroChunk = false;
            receivingContentLength = 0;
        }

        esp_tls_conn_state_t getTlsState() const
        {
            if (handle == nullptr)
            {
                return ESP_TLS_INIT;
            }

            esp_tls_conn_state_t state{};
            int res = esp_tls_get_conn_state(handle, &state);
            if (res != ESP_OK)
            {
                return ESP_TLS_INIT;
            }

            return state;
        }

        bool isTlsStarted()
        {
            esp_tls_conn_state_t state = getTlsState();
            return state == ESP_TLS_DONE || state == ESP_TLS_HANDSHAKE || state == ESP_TLS_CONNECTING;
        }

        Method currentMethod;
        bool keepAlive;

        int port;
        Mode mode;
        ESPHttpxClientState currentState;
        ESPHttpxClientEventHandler eventHandler;
        esp_tls_t *handle;

        ESPHttpxClientWriteHandler writeHandler;
        ssize_t currentWriteLen;
        size_t currentWriteOffset;
        size_t currentWriteTotal;
        bool sendingZeroChunk;

        const char *cert;
        size_t certLen;
        esp_tls_cfg_t config;

        uint8_t dataBuffer[dataBufferSize];
        bool sentFirstQueryParam;

        size_t headerBufferOffset;
        char currentHeaderBuffer[headerBufferSize];
        size_t terminatorMatchCounts[TERMINATORS_COUNT]{};
        size_t terminatorsLengths[TERMINATORS_COUNT]{};

        ssize_t contentLength;
        ssize_t contentSentLen;

        bool isReceivingChunked;
        size_t currentChunkSize;
        size_t currentChunkOffset;
        char chunkSizeBuf[32]{};
        size_t receivingContentLength;

        bool hasRedirection;
        bool redirectionProcessed;
        size_t redirectionCount;
        size_t maxRedirections;
    };
}

#endif
