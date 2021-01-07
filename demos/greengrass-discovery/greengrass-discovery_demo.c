/*
 * AWS IoT Device SDK for Embedded C 202012.01
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* POSIX includes. */
#include <unistd.h>

/* Include Demo Config as the first non-system header. */
#include "demo_config.h"

/* Common HTTP demo utilities. */
#include "http_demo_utils.h"

/* HTTP API header. */
#include "core_http_client.h"

/* core JSON include. */
#include "core_json.h"

/* MQTT API headers. */
#include "core_mqtt.h"
#include "core_mqtt_state.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* OpenSSL transport header. */
#include "openssl_posix.h"

/* Check that AWS IoT Core endpoint is defined. */
#ifndef AWS_IOT_ENDPOINT
    #error "AWS_IOT_ENDPOINT must be defined to your AWS IoT Core endpoint."
#endif

/* Check that TLS port used for AWS IoT Core is defined. */
#ifndef AWS_HTTPS_PORT
    #error "Please define a AWS_HTTPS_PORT."
#endif

/* Check that a path for HTTP Method GET is defined. */
#ifndef GET_PATH
    #error "Please define a POST_PATH."
#endif

/* Check that a path for Root CA certificate is defined. */
#ifndef ROOT_CA_CERT_PATH
    #error "Please define a ROOT_CA_CERT_PATH."
#endif

/* Check that a path for the client certificate is defined. */
#ifndef CLIENT_CERT_PATH
    #error "Please define a CLIENT_CERT_PATH."
#endif

/* Check that a path for the client's private key is defined. */
#ifndef CLIENT_PRIVATE_KEY_PATH
    #error "Please define a CLIENT_PRIVATE_KEY_PATH."
#endif

/**
 * @brief ALPN protocol name to be sent as part of the ClientHello message.
 *
 * @note When using ALPN, port 443 must be used to connect to AWS IoT Core.
 */
#define IOT_CORE_ALPN_PROTOCOL_NAME    "\x0ex-amzn-http-ca"

/* Check that transport timeout for transport send and receive is defined. */
#ifndef TRANSPORT_SEND_RECV_TIMEOUT_MS
    #define TRANSPORT_SEND_RECV_TIMEOUT_MS    ( 1000 )
#endif

/* Check that size of the user buffer is defined. */
#ifndef USER_BUFFER_LENGTH
    #define USER_BUFFER_LENGTH    ( 2500 )
#endif

/* Path to store the GG Core certificate. */
#ifndef GG_ROOT_CA_PATH
    #define GG_ROOT_CA_PATH    "certificates/GGCoreCertificate.crt"
#endif

#define GG_ROOT_CA_PATH_TEST "certificates/GGCoreCertificateWithoutModification"

/**
 * @brief The length of the AWS IoT Endpoint.
 */
#define AWS_IOT_ENDPOINT_LENGTH    ( sizeof( AWS_IOT_ENDPOINT ) - 1 )

/**
 * @brief The length of the HTTP POST method.
 */
#define HTTP_METHOD_POST_LENGTH    ( sizeof( HTTP_METHOD_POST ) - 1 )

/**
 * @brief The length of the HTTP POST path.
 */
#define POST_PATH_LENGTH           ( sizeof( POST_PATH ) - 1 )


/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                  ( 1000U )

/**
 * @brief A buffer used in the demo for storing HTTP request headers and
 * HTTP response headers and body.
 *
 * @note This demo shows how the same buffer can be re-used for storing the HTTP
 * response after the HTTP request is sent out. However, the user can also
 * decide to use separate buffers for storing the HTTP request and response.
 */
static uint8_t userBuffer[ USER_BUFFER_LENGTH ];

/*-----------------------------------------------------------*/

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext
{
    OpensslParams_t * pParams;
};

/*-----------------------------------------------------------*/

/**
 * @brief Connect to HTTP server with reconnection retries.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
static int32_t connectToServerHTTP( NetworkContext_t * pNetworkContext );

/**
 * @brief Send an HTTP request based on a specified method and path, then
 * print the response received from the server.
 *
 * @param[in] pTransportInterface The transport interface for making network calls.
 * @param[in] pMethod The HTTP request method.
 * @param[in] methodLen The length of the HTTP request method.
 * @param[in] pPath The Request-URI to the objects of interest.
 * @param[in] pathLen The length of the Request-URI.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on success.
 */
static int32_t sendHttpRequest( const TransportInterface_t * pTransportInterface,
                                const char * pMethod,
                                size_t methodLen,
                                const char * pPath,
                                size_t pathLen,
                                char ** ppcJSONFile,
                                uint32_t * plJSONFileLength );

/*-----------------------------------------------------------*/

static int32_t connectToServerHTTP( NetworkContext_t * pNetworkContext )
{
    int32_t returnStatus = EXIT_FAILURE;
    /* Status returned by OpenSSL transport implementation. */
    OpensslStatus_t opensslStatus;
    /* Credentials to establish the TLS connection. */
    OpensslCredentials_t opensslCredentials;
    /* Information about the server to send the HTTP requests. */
    ServerInfo_t serverInfo;

    /* Initialize TLS credentials. */
    ( void ) memset( &opensslCredentials, 0, sizeof( opensslCredentials ) );
    opensslCredentials.pClientCertPath = CLIENT_CERT_PATH;
    opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH;
    opensslCredentials.pRootCaPath = ROOT_CA_CERT_PATH;
    opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;

    /* ALPN is required when communicating to AWS IoT Core over port 443 through HTTP. */
    if( AWS_HTTPS_PORT == 443 )
    {
        opensslCredentials.pAlpnProtos = IOT_CORE_ALPN_PROTOCOL_NAME;
        opensslCredentials.alpnProtosLen = strlen( IOT_CORE_ALPN_PROTOCOL_NAME );
    }

    /* Initialize server information. */
    serverInfo.pHostName = AWS_IOT_ENDPOINT;
    serverInfo.hostNameLength = AWS_IOT_ENDPOINT_LENGTH;
    serverInfo.port = AWS_HTTPS_PORT;

    /* Establish a TLS session with the HTTP server. This example connects
     * to the HTTP server as specified in AWS_IOT_ENDPOINT and AWS_HTTPS_PORT
     * in demo_config.h. */
    LogInfo( ( "Establishing a TLS session to %.*s:%d.",
               ( int32_t ) AWS_IOT_ENDPOINT_LENGTH,
               AWS_IOT_ENDPOINT,
               AWS_HTTPS_PORT ) );
    opensslStatus = Openssl_Connect( pNetworkContext,
                                     &serverInfo,
                                     &opensslCredentials,
                                     TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                     TRANSPORT_SEND_RECV_TIMEOUT_MS );

    if( opensslStatus == OPENSSL_SUCCESS )
    {
        returnStatus = EXIT_SUCCESS;
    }
    else
    {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int32_t sendHttpRequest( const TransportInterface_t * pTransportInterface,
                                const char * pMethod,
                                size_t methodLen,
                                const char * pPath,
                                size_t pathLen,
                                char ** ppcJSONFile,
                                uint32_t * plJSONFileLength )
{
    /* Return value of this method. */
    int32_t returnStatus = EXIT_SUCCESS;

    /* Configurations of the initial request headers that are passed to
     * #HTTPClient_InitializeRequestHeaders. */
    HTTPRequestInfo_t requestInfo;
    /* Represents a response returned from an HTTP server. */
    HTTPResponse_t response;
    /* Represents header data that will be sent in an HTTP request. */
    HTTPRequestHeaders_t requestHeaders;

    /* Return value of all methods from the HTTP Client library API. */
    HTTPStatus_t httpStatus = HTTPSuccess;

    assert( pMethod != NULL );
    assert( pPath != NULL );

    /* Initialize all HTTP Client library API structs to 0. */
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );
    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );

    /* Initialize the request object. */
    requestInfo.pHost = AWS_IOT_ENDPOINT;
    requestInfo.hostLen = AWS_IOT_ENDPOINT_LENGTH;
    requestInfo.pMethod = pMethod;
    requestInfo.methodLen = methodLen;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = pathLen;

    /* Set "Connection" HTTP header to "keep-alive" so that multiple requests
     * can be sent over the same established TCP connection. */
    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    /* Set the buffer used for storing request headers. */
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      &requestInfo );

    if( httpStatus == HTTPSuccess )
    {
        /* Initialize the response object. The same buffer used for storing
         * request headers is reused here. */
        response.pBuffer = userBuffer;
        response.bufferLen = USER_BUFFER_LENGTH;

        LogInfo( ( "Sending HTTP %.*s request to %.*s%.*s...",
                   ( int32_t ) requestInfo.methodLen, requestInfo.pMethod,
                   ( int32_t ) AWS_IOT_ENDPOINT_LENGTH, AWS_IOT_ENDPOINT,
                   ( int32_t ) requestInfo.pathLen, requestInfo.pPath ) );
        LogDebug( ( "Request Headers:\n%.*s\n"
                    "Request Body:\n%.*s\n",
                    ( int32_t ) requestHeaders.headersLen,
                    ( char * ) requestHeaders.pBuffer ) );

        /* Send the request and receive the response. */
        httpStatus = HTTPClient_Send( pTransportInterface,
                                      &requestHeaders,
                                      NULL,
                                      0,
                                      &response,
                                      0 );
    }
    else
    {
        LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                    HTTPClient_strerror( httpStatus ) ) );
    }

    if( httpStatus == HTTPSuccess )
    {
        LogInfo( ( "Received HTTP response from %.*s%.*s...\n"
                   "Response Headers:\n%.*s\n"
                   "Response Status:\n%u\n"
                   "Response Body:\n%.*s\n",
                   ( int32_t ) AWS_IOT_ENDPOINT_LENGTH, AWS_IOT_ENDPOINT,
                   ( int32_t ) requestInfo.pathLen, requestInfo.pPath,
                   ( int32_t ) response.headersLen, response.pHeaders,
                   response.statusCode,
                   ( int32_t ) response.bodyLen, response.pBody ) );

        /* Set the output parameters. */
        *ppcJSONFile = response.pBody;
        *plJSONFileLength = response.bodyLen;
    }
    else
    {
        LogError( ( "Failed to send HTTP %.*s request to %.*s%.*s: Error=%s.",
                    ( int32_t ) requestInfo.methodLen, requestInfo.pMethod,
                    ( int32_t ) AWS_IOT_ENDPOINT_LENGTH, AWS_IOT_ENDPOINT,
                    ( int32_t ) requestInfo.pathLen, requestInfo.pPath,
                    HTTPClient_strerror( httpStatus ) ) );
    }

    if( httpStatus != HTTPSuccess )
    {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static void prvConvertCertificateJSONToString( char * certbuf,
                                               size_t certlen )
{
    FILE * fd;
    uint32_t ulReadIndex = 1, ulWriteIndex = 0;

    do
    {
        if( ( certbuf[ ulReadIndex - ( uint32_t ) 1 ] == '\\' ) &&
            ( certbuf[ ulReadIndex ] == 'n' ) )
        {
            certbuf[ ulWriteIndex ] = '\n';
            ulReadIndex++;
        }
        else
        {
            certbuf[ ulWriteIndex ] =
                certbuf[ ulReadIndex - ( uint32_t ) 1 ];
        }

        ulReadIndex++;
        ulWriteIndex++;
    } while( ulReadIndex < certlen );

    fd = fopen( GG_ROOT_CA_PATH, "w" );

    /* Write to the file. */
    fwrite( certbuf, sizeof(char), ulWriteIndex, fd );

    fclose( fd );
}

/*-----------------------------------------------------------*/

static int32_t prvGGDGetCertificate( char * pcJSONFile,
                                     const uint32_t ulJSONFileSize,
                                     char ** pucCert )
{
    int32_t returnStatus = EXIT_FAILURE;

    /* TODO: This is just grabbing the first CA. Need to update to match
     * multi CA case. */
    char query[] = "GGGroups[0].CAs[0]";
    size_t queryLength = sizeof( query ) - 1;
    char * value;
    size_t valueLength;
    JSONStatus_t result;
    char * certbuf = NULL;
    uint32_t ulReadIndex = 1, ulWriteIndex = 0;
    int32_t pulCertLen = 0;

    result = JSON_Search( pcJSONFile,
                          ulJSONFileSize,
                          query,
                          queryLength,
                          &value,
                          &valueLength );

    if( result == JSONSuccess )
    {
        certbuf = ( char * ) malloc( valueLength + 1 );
        memset( certbuf, 0x00, valueLength + 1 );
        /* strip trailing \n character. */
        memcpy( certbuf, value, valueLength );
        prvConvertCertificateJSONToString( certbuf, valueLength );
        *pucCert = GG_ROOT_CA_PATH;
        returnStatus = EXIT_SUCCESS;
        free(certbuf);
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int32_t prvGGDGetIPOnInterface( char * pcJSONFile,
                                       const uint32_t ulJSONFileSize,
                                       ServerInfo_t * pucTargetInterface )
{
    int32_t returnStatus = EXIT_FAILURE;
    int32_t hasFoundIP = 0;
    int32_t hasFoundPort = 0;
    char hostAddressQuery[] = "GGGroups[0].Cores[0].Connectivity[0].HostAddress";
    char hostPortQuery[] = "GGGroups[0].Cores[0].Connectivity[0].PortNumber";
    size_t hostAddressQueryLength = sizeof( hostAddressQuery ) - 1;
    size_t hostPortQueryLength = sizeof( hostPortQuery ) - 1;
    char * value;
    size_t valueLength;
    JSONStatus_t result;

    result = JSON_Search( pcJSONFile,
                          ulJSONFileSize,
                          hostAddressQuery,
                          hostAddressQueryLength,
                          &value,
                          &valueLength );

    if( result == JSONSuccess )
    {
        char * addressbuf = ( char * ) malloc( valueLength + 1 );
        memset( addressbuf, 0x00, valueLength + 1 );
        memcpy( addressbuf, value, valueLength );

        /*pucTargetInterface->pHostName = FreeRTOS_inet_addr( addressbuf ); */
        pucTargetInterface->pHostName = addressbuf;
        pucTargetInterface->hostNameLength = valueLength;
        returnStatus = EXIT_SUCCESS;
        hasFoundIP = 1;
    }

    value = NULL;
    valueLength = 0;

    result = JSON_Search( pcJSONFile,
                          ulJSONFileSize,
                          hostPortQuery,
                          hostPortQueryLength,
                          &value,
                          &valueLength );

    if( result == JSONSuccess )
    {
        /* TODO: Define the 10 in a macro. */
        pucTargetInterface->port = strtoul( value, NULL, 10 );
        returnStatus = EXIT_SUCCESS;
        hasFoundIP = 1;
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "The Greengrass core address obtained is %.*s:%d",
                   pucTargetInterface->hostNameLength,
                   pucTargetInterface->pHostName,
                   pucTargetInterface->port ) );
    }
    else
    {
        LogInfo( ( "Failed to retrieve the Greengrass core address." ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static uint32_t generateRandomNumber()
{
    return( rand() );
}

/*-----------------------------------------------------------*/

static int connectToServer( NetworkContext_t * pNetworkContext,
                            ServerInfo_t * pServerInfo,
                            char * pRootCaPath )
{
    int returnStatus = EXIT_SUCCESS;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    OpensslStatus_t opensslStatus = OPENSSL_SUCCESS;
    BackoffAlgorithmContext_t reconnectParams;
    OpensslCredentials_t opensslCredentials;
    uint16_t nextRetryBackOff;
    
    /* Initialize credentials for establishing TLS session. */
    memset( &opensslCredentials, 0, sizeof( OpensslCredentials_t ) );
    opensslCredentials.pRootCaPath = GG_ROOT_CA_PATH;

    /* If #CLIENT_USERNAME is defined, username/password is used for authenticating
     * the client. */
    opensslCredentials.pClientCertPath = CLIENT_CERT_PATH;
    opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH;

    /* AWS IoT requires devices to send the Server Name Indication (SNI)
     * extension to the Transport Layer Security (TLS) protocol and provide
     * the complete endpoint address in the host_name field. Details about
     * SNI for AWS IoT can be found in the link below.
     * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html */
    //opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;

    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       CONNECTION_RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase until maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects
         * to the MQTT broker as specified in AWS_IOT_ENDPOINT and AWS_MQTT_PORT
         * at the demo config header. */
        LogInfo( ( "Establishing a TLS session to %.*s:%d.",
                   pServerInfo->hostNameLength,
                   pServerInfo->pHostName,
                   pServerInfo->port ) );
        opensslStatus = Openssl_Connect( pNetworkContext,
                                         pServerInfo,
                                         &opensslCredentials,
                                         TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                         TRANSPORT_SEND_RECV_TIMEOUT_MS );

        if( opensslStatus != OPENSSL_SUCCESS )
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                returnStatus = EXIT_FAILURE;
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection "
                           "after %hu ms backoff.",
                           ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( opensslStatus != OPENSSL_SUCCESS ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of demo.
 *
 * This example resolves the AWS IoT Core endpoint, establishes a TCP connection,
 * performs a mutually authenticated TLS handshake occurs such that all further
 * communication is encrypted. After which, HTTP Client Library API is used to
 * make a POST request to AWS IoT Core in order to publish a message to a topic
 * named topic with QoS=1 so that all clients subscribed to the topic receive
 * the message at least once. Any possible errors are also logged.
 *
 * @note This example is single-threaded and uses statically allocated memory.
 *
 */
int main( int argc,
          char ** argv )
{
    /* Return value of main. */
    int32_t returnStatus = EXIT_SUCCESS;
    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t transportInterface;
    /* The network context for the transport layer interface. */
    NetworkContext_t networkContext;
    OpensslParams_t opensslParams;
    char * pcJSONFile = NULL;
    uint32_t * ulJSONFileLength = 0;

    /* MQTT specific credentials. */
    ServerInfo_t xServerInfo = { 0 };
    OpensslCredentials_t OpensslCredentials = { 0 };


    ( void ) argc;
    ( void ) argv;

    /* Set the pParams member of the network context with desired transport. */
    networkContext.pParams = &opensslParams;

    /**************************** Connect. ******************************/

    /* Establish TLS connection on top of TCP connection using OpenSSL. */
    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "Performing TLS handshake on top of the TCP connection." ) );

        /* Attempt to connect to the HTTP server. If connection fails, retry after
         * a timeout. Timeout value will be exponentially increased till the maximum
         * attempts are reached or maximum timeout value is reached. The function
         * returns EXIT_FAILURE if the TCP connection cannot be established to
         * broker after configured number of attempts. */
        returnStatus = connectToServerWithBackoffRetries( connectToServerHTTP,
                                                          &networkContext );

        if( returnStatus == EXIT_FAILURE )
        {
            /* Log error to indicate connection failure after all
             * reconnect attempts are over. */
            LogError( ( "Failed to connect to HTTP server %.*s.",
                        ( int32_t ) AWS_IOT_ENDPOINT_LENGTH,
                        AWS_IOT_ENDPOINT ) );
        }
    }

    /* Define the transport interface. */
    if( returnStatus == EXIT_SUCCESS )
    {
        ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
        transportInterface.recv = Openssl_Recv;
        transportInterface.send = Openssl_Send;
        transportInterface.pNetworkContext = &networkContext;
    }

    /*********************** Send HTTPS request. ************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        returnStatus = sendHttpRequest( &transportInterface,
                                        HTTP_METHOD_GET,
                                        strlen( HTTP_METHOD_GET ),
                                        GET_PATH,
                                        strlen( GET_PATH ),
                                        &pcJSONFile,
                                        &ulJSONFileLength );
    }

    /************************** Disconnect. *****************************/

    /* End TLS session, then close TCP connection. */
    ( void ) Openssl_Disconnect( &networkContext );

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Parse the retrieved JSON to get the GG Core certificate. */
        returnStatus = prvGGDGetCertificate( pcJSONFile,
                                             ulJSONFileLength,
                                             &OpensslCredentials.pRootCaPath );
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "The root ca path is %s.", OpensslCredentials.pRootCaPath ) );
        /* Parse the retrieved JSON to get the GG Core certificate. */
        returnStatus = prvGGDGetIPOnInterface( pcJSONFile,
                                               ulJSONFileLength,
                                               &xServerInfo );
    }

    /**********************MQTT Operations *********************************/
    if( returnStatus == EXIT_SUCCESS )
    {
        memset(&networkContext,0, sizeof(networkContext));
        /* Set the pParams member of the network context with desired transport. */
        networkContext.pParams = &opensslParams;

        returnStatus = connectToServer( &networkContext,
                                        &xServerInfo,
                                        OpensslCredentials.pRootCaPath );
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Log message indicating an iteration completed successfully. */
        LogInfo( ( "Demo completed successfully." ) );
    }

    return returnStatus;
}
