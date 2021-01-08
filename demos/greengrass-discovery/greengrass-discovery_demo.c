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

/* Clock for timer. */
#include "clock.h"

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
    #define GG_ROOT_CA_PATH                        "certificates/GGCoreCertificate.crt"
#endif

#define GG_ROOT_CA_PATH_TEST                       "certificates/GGCoreCertificateWithoutModification"

/* GG Core MQTT publish messages. */
#define ggdDEMO_MAX_MQTT_MESSAGES                  65536
#define ggdDEMO_MAX_MQTT_MSG_SIZE                  500
#define ggdDEMO_MQTT_MSG_TOPIC                     "freertos/demos/ggd"
#define ggdDEMO_MQTT_MSG_DISCOVERY                 "{\"Hello #%lu from Device using CSDK.\"}"
#define ggdDEMO_MQTT_RESPONSE_TOPIC                ggdDEMO_MQTT_MSG_TOPIC "/response"

/**
 * @brief The length of the AWS IoT Endpoint.
 */
#define AWS_IOT_ENDPOINT_LENGTH                    ( sizeof( AWS_IOT_ENDPOINT ) - 1 )

/**
 * @brief The length of the HTTP POST method.
 */
#define HTTP_METHOD_POST_LENGTH                    ( sizeof( HTTP_METHOD_POST ) - 1 )

/**
 * @brief The length of the HTTP POST path.
 */
#define POST_PATH_LENGTH                           ( sizeof( POST_PATH ) - 1 )

/**
 * @brief Length of client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH                   ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS              ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS      ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS           ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                    ( 1000U )

/**
 * @brief Timeout for MQTT_ProcessLoop in milliseconds.
 */
#define PROCESS_LOOP_TIMEOUT_MS                    ( 700U )

/**
 * @brief The maximum number of times to call MQTT_ProcessLoop() when polling
 * for a specific packet from the broker.
 */
#define MQTT_PROCESS_LOOP_PACKET_WAIT_COUNT_MAX    ( 2U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 *  between two Control Packets.
 *
 *  It is the responsibility of the Client to ensure that the interval between
 *  Control Packets being sent does not exceed the this Keep Alive value. In the
 *  absence of sending any other Control Packets, the Client MUST send a
 *  PINGREQ Packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS           ( 60U )

/**
 * @brief The MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING                             "?SDK=" OS_NAME "&Version=" OS_VERSION "&Platform=" HARDWARE_PLATFORM_NAME "&MQTTLib=" MQTT_LIB

/**
 * @brief The length of the MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING_LENGTH                      ( ( uint16_t ) ( sizeof( METRICS_STRING ) - 1 ) )

/**
 * @brief A buffer used in the demo for storing HTTP request headers and
 * HTTP response headers and body.
 *
 * @note This demo shows how the same buffer can be re-used for storing the HTTP
 * response after the HTTP request is sent out. However, the user can also
 * decide to use separate buffers for storing the HTTP request and response.
 */
static uint8_t userBuffer[ USER_BUFFER_LENGTH ];

/**
 * @brief MQTT packet type received from the MQTT broker.
 *
 * @note Only on receiving incoming PUBLISH, SUBACK, and UNSUBACK, this
 * variable is updated. For MQTT packets PUBACK and PINGRESP, the variable is
 * not updated since there is no need to specifically wait for it in this demo.
 * A single variable suffices as this demo uses single task and requests one operation
 * (of PUBLISH, SUBSCRIBE, UNSUBSCRIBE) at a time before expecting response from
 * the broker. Hence it is not possible to receive multiple packets of type PUBLISH,
 * SUBACK, and UNSUBACK in a single call of #prvWaitForPacket.
 * For a multi task application, consider a different method to wait for the packet, if needed.
 */
static uint16_t usPacketTypeReceived = 0U;

/**
 * @brief Server information to which a TLS connection needs to be established.
 */
static ServerInfo_t serverInfo;

/**
 * @brief The root CA file path.
 */
static char * rootCAFilePath;


/*-----------------------------------------------------------*/

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext
{
    OpensslParams_t * pParams;
};

/*-----------------------------------------------------------*/

/******************** TLS funtions ****************************/
static int32_t connectToServer( NetworkContext_t * pNetworkContext )
{
    int32_t returnStatus = EXIT_FAILURE;
    /* Status returned by OpenSSL transport implementation. */
    OpensslStatus_t opensslStatus;
    /* Credentials to establish the TLS connection. */
    OpensslCredentials_t opensslCredentials;

    /* Initialize TLS credentials. */
    ( void ) memset( &opensslCredentials, 0, sizeof( opensslCredentials ) );
    opensslCredentials.pClientCertPath = CLIENT_CERT_PATH;
    opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH;
    opensslCredentials.pRootCaPath = rootCAFilePath;
    opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;

    /* ALPN is required when communicating to AWS IoT Core over port 443 through HTTP. */
    if( AWS_HTTPS_PORT == 443 )
    {
        opensslCredentials.pAlpnProtos = IOT_CORE_ALPN_PROTOCOL_NAME;
        opensslCredentials.alpnProtosLen = strlen( IOT_CORE_ALPN_PROTOCOL_NAME );
    }

    /* Establish a TLS session with the HTTP server. This example connects
     * to the HTTP server as specified in AWS_IOT_ENDPOINT and AWS_HTTPS_PORT
     * in demo_config.h. */
    LogInfo( ( "Establishing a TLS session to %.*s:%d.",
               ( int32_t ) serverInfo.hostNameLength,
               serverInfo.pHostName,
               serverInfo.port ) );
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

/******************** HTTP funtions ****************************/

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
        *ppcJSONFile = ( char * ) response.pBody;
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

/******************** JSON funtions ****************************/

static void prvStoreCertificateinFile( char * certbuf,
                                       size_t certlen )
{
    FILE * fd;
    uint32_t ulReadIndex = 1, ulWriteIndex = 0;

    /* Convert 2 character long "\n" from JSON to a single character '\n'. */
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

    /* Write the certificate in a file at location GG_ROOT_CA_PATH. */
    fd = fopen( GG_ROOT_CA_PATH, "w" );

    if( fd != NULL )
    {
        /* Write to the file. */
        fwrite( certbuf, sizeof( char ), ulWriteIndex, fd );

        /* Close file. */
        fclose( fd );
    }
    else
    {
        LogError( ( "Writing certificate to the file %s failed.", GG_ROOT_CA_PATH ) );
    }
}

/*-----------------------------------------------------------*/

static int32_t prvGGDGetCertificate( char * pcJSONFile,
                                     const uint32_t ulJSONFileSize )
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
        prvStoreCertificateinFile( certbuf, valueLength );
        free( certbuf );
        returnStatus = EXIT_SUCCESS;
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
                   ( int ) pucTargetInterface->hostNameLength,
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

/******************** MQTT funtions ****************************/

static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        LogInfo( ( "Incoming publish received." ) );
        usPacketTypeReceived = MQTT_PACKET_TYPE_PUBLISH;
        LogInfo( ( "Incoming publish: %.*s .......\r\n\r\n",
                   ( int32_t ) pDeserializedInfo->pPublishInfo->payloadLength,
                   ( char * ) pDeserializedInfo->pPublishInfo->pPayload ) );
    }
    else
    {
        usPacketTypeReceived = pPacketInfo->type;
        LogInfo( ( "Incoming packet type is %02X.", pPacketInfo->type ) );
    }
}

/*-----------------------------------------------------------*/

static int establishMqttSession( MQTTContext_t * pMqttContext,
                                 bool createCleanSession,
                                 bool * pSessionPresent )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTConnectInfo_t connectInfo = { 0 };

    assert( pMqttContext != NULL );
    assert( pSessionPresent != NULL );

    /* Establish MQTT session by sending a CONNECT packet. */

    /* If #createCleanSession is true, start with a clean session
     * i.e. direct the MQTT broker to discard any previous session data.
     * If #createCleanSession is false, directs the broker to attempt to
     * reestablish a session which was already present. */
    connectInfo.cleanSession = createCleanSession;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    connectInfo.pClientIdentifier = IOT_THING_NAME;
    connectInfo.clientIdentifierLength = strlen( IOT_THING_NAME );

    /* The maximum time interval in seconds which is allowed to elapse
     * between two Control Packets.
     * It is the responsibility of the Client to ensure that the interval between
     * Control Packets being sent does not exceed the this Keep Alive value. In the
     * absence of sending any other Control Packets, the Client MUST send a
     * PINGREQ Packet. */
    connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

    /* Use the username and password for authentication, if they are defined.
     * Refer to the AWS IoT documentation below for details regarding client
     * authentication with a username and password.
     * https://docs.aws.amazon.com/iot/latest/developerguide/enhanced-custom-authentication.html
     * An authorizer setup needs to be done, as mentioned in the above link, to use
     * username/password based client authentication.
     *
     * The username field is populated with voluntary metrics to AWS IoT.
     * The metrics collected by AWS IoT are the operating system, the operating
     * system's version, the hardware platform, and the MQTT Client library
     * information. These metrics help AWS IoT improve security and provide
     * better technical support.
     *
     * If client authentication is based on username/password in AWS IoT,
     * the metrics string is appended to the username to support both client
     * authentication and metrics collection. */
    #ifdef CLIENT_USERNAME
        connectInfo.pUserName = CLIENT_USERNAME_WITH_METRICS;
        connectInfo.userNameLength = strlen( CLIENT_USERNAME_WITH_METRICS );
        connectInfo.pPassword = CLIENT_PASSWORD;
        connectInfo.passwordLength = strlen( CLIENT_PASSWORD );
    #else
        connectInfo.pUserName = METRICS_STRING;
        connectInfo.userNameLength = METRICS_STRING_LENGTH;
        /* Password for authentication is not used. */
        connectInfo.pPassword = NULL;
        connectInfo.passwordLength = 0U;
    #endif /* ifdef CLIENT_USERNAME */

    /* Send MQTT CONNECT packet to broker. */
    mqttStatus = MQTT_Connect( pMqttContext, &connectInfo, NULL, CONNACK_RECV_TIMEOUT_MS, pSessionPresent );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "Connection with MQTT broker failed with status %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogInfo( ( "MQTT connection successfully established with broker.\n\n" ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static MQTTStatus_t prvWaitForPacket( MQTTContext_t * pxMQTTContext,
                                      uint16_t usPacketType )
{
    uint8_t ucCount = 0U;
    MQTTStatus_t xMQTTStatus = MQTTSuccess;

    /* Reset the packet type received. */
    usPacketTypeReceived = 0U;

    while( ( usPacketTypeReceived != usPacketType ) &&
           ( ucCount++ < MQTT_PROCESS_LOOP_PACKET_WAIT_COUNT_MAX ) &&
           ( xMQTTStatus == MQTTSuccess ) )
    {
        /* Event callback will set #usPacketTypeReceived when receiving appropriate packet. This
         * will wait for at most PROCESS_LOOP_TIMEOUT_MS. */
        xMQTTStatus = MQTT_ProcessLoop( pxMQTTContext, PROCESS_LOOP_TIMEOUT_MS );
    }

    if( ( xMQTTStatus != MQTTSuccess ) || ( usPacketTypeReceived != usPacketType ) )
    {
        LogError( ( "MQTT_ProcessLoop failed to receive packet: Packet type=%02X, LoopDuration=%u, Status=%s",
                    usPacketType,
                    ( PROCESS_LOOP_TIMEOUT_MS * ucCount ),
                    MQTT_Status_strerror( xMQTTStatus ) ) );
    }

    return xMQTTStatus;
}

/*-----------------------------------------------------------*/

static int subscribeToResponseTopic( MQTTContext_t * pxMQTTContext )
{
    MQTTStatus_t xResult = MQTTSuccess;
    int xStatus = EXIT_FAILURE;
    MQTTSubscribeInfo_t xMQTTSubscription[ 1 ];
    uint32_t ulTopicCount = 0U;
    uint16_t usSubscribePacketIdentifier;

    /* Some fields not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTSubscription, 0x00, sizeof( xMQTTSubscription ) );

    /* Get a unique packet id. */
    usSubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Subscribe to the mqttexampleTOPIC topic filter. This example subscribes to
     * only one topic and uses QoS0. */
    xMQTTSubscription[ 0 ].qos = MQTTQoS0;
    xMQTTSubscription[ 0 ].pTopicFilter = ggdDEMO_MQTT_RESPONSE_TOPIC;
    xMQTTSubscription[ 0 ].topicFilterLength = ( uint16_t ) strlen( ggdDEMO_MQTT_RESPONSE_TOPIC );

    /* The client is now connected to the broker. Subscribe to the topic
     * as specified in mqttexampleTOPIC at the top of this file by sending a
     * subscribe packet then waiting for a subscribe acknowledgment (SUBACK).
     * This client will then publish to the same topic it subscribed to, so it
     * will expect all the messages it sends to the broker to be sent back to it
     * from the broker. This demo uses QOS0 in Subscribe, therefore, the Publish
     * messages received from the broker will have QOS0. */
    LogInfo( ( "Attempt to subscribe to the MQTT topic %s.", ggdDEMO_MQTT_RESPONSE_TOPIC ) );
    xResult = MQTT_Subscribe( pxMQTTContext,
                              xMQTTSubscription,
                              sizeof( xMQTTSubscription ) / sizeof( MQTTSubscribeInfo_t ),
                              usSubscribePacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to SUBSCRIBE to MQTT topic %s. Error=%s",
                    ggdDEMO_MQTT_RESPONSE_TOPIC, MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        xStatus = EXIT_SUCCESS;
        LogInfo( ( "SUBSCRIBE sent for topic %s to broker.", ggdDEMO_MQTT_RESPONSE_TOPIC ) );

        /* Process incoming packet from the broker. After sending the subscribe, the
         * client may receive a publish before it receives a subscribe ack. Therefore,
         * call generic incoming packet processing function. Since this demo is
         * subscribing to the topic to which no one is publishing, probability of
         * receiving Publish message before subscribe ack is zero; but application
         * must be ready to receive any packet.  This demo uses the generic packet
         * processing function everywhere to highlight this fact. */
        xResult = prvWaitForPacket( pxMQTTContext, MQTT_PACKET_TYPE_SUBACK );

        if( xResult != MQTTSuccess )
        {
            xStatus = EXIT_FAILURE;
        }
        else
        {
            LogInfo( ( "Subscribed to the topic %s.", ggdDEMO_MQTT_RESPONSE_TOPIC ) );
        }
        
    }

    return xStatus;
}

/*-----------------------------------------------------------*/

static int mqttPublishLoop( MQTTContext_t * pxMQTTContext )
{
    const char * pcTopic = ggdDEMO_MQTT_MSG_TOPIC;
    uint32_t ulMessageCounter;
    char cBuffer[ ggdDEMO_MAX_MQTT_MSG_SIZE ];
    MQTTStatus_t xResult;
    MQTTPublishInfo_t xMQTTPublishInfo;
    int returnStatus = EXIT_SUCCESS;
    uint16_t usPublishPacketIdentifier;

    /* Some fields are not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTPublishInfo, 0x00, sizeof( xMQTTPublishInfo ) );

    /* This demo uses QoS0. */
    xMQTTPublishInfo.qos = MQTTQoS0;
    xMQTTPublishInfo.retain = false;
    xMQTTPublishInfo.pTopicName = pcTopic;
    xMQTTPublishInfo.topicNameLength = ( uint16_t ) strlen( pcTopic );

    for( ulMessageCounter = 0; ulMessageCounter < ( uint32_t ) ggdDEMO_MAX_MQTT_MESSAGES; ulMessageCounter++ )
    {
        xMQTTPublishInfo.pPayload = ( const void * ) cBuffer;
        xMQTTPublishInfo.payloadLength = ( uint32_t ) sprintf( cBuffer, ggdDEMO_MQTT_MSG_DISCOVERY, ( long unsigned int ) ulMessageCounter );

        /* Get a unique packet id. */
        usPublishPacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

        /* Send PUBLISH packet. Packet ID is not used for a QoS1 publish. */
        xResult = MQTT_Publish( pxMQTTContext, &xMQTTPublishInfo, usPublishPacketIdentifier );

        if( xResult != MQTTSuccess )
        {
            returnStatus = EXIT_FAILURE;
            LogError( ( "Failed to send PUBLISH message to broker: Topic=%s, Error=%s",
                        pcTopic,
                        MQTT_Status_strerror( xResult ) ) );
        }
        else
        {
            LogInfo( ( "Sent PUBLISH Topic=%s, payload=%s", pcTopic, cBuffer ) );
        }

        /* Wait for a second before the next publish. */
        Clock_SleepMs( 1000 );

        /* Check if there is a response incoming publish.*/
        prvWaitForPacket( pxMQTTContext, MQTT_PACKET_TYPE_PUBLISH );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int retriveGGCoreInfo( ServerInfo_t * pServerInfo )
{
    /* Return value of main. */
    int32_t returnStatus = EXIT_SUCCESS;
    /* The transport layer interface used by the HTTP Client library. */
    TransportInterface_t transportInterface;
    /* The network context for the transport layer interface. */
    NetworkContext_t networkContext;
    OpensslParams_t opensslParams;
    char * pcJSONFile = NULL;
    uint32_t ulJSONFileLength = 0;
    OpensslCredentials_t OpensslCredentials = { 0 };

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
        /* Initialize server information. */
        serverInfo.pHostName = AWS_IOT_ENDPOINT;
        serverInfo.hostNameLength = AWS_IOT_ENDPOINT_LENGTH;
        serverInfo.port = AWS_HTTPS_PORT;
        rootCAFilePath = ROOT_CA_CERT_PATH;
        returnStatus = connectToServerWithBackoffRetries( connectToServer,
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
                                             ulJSONFileLength );
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "The root ca file path is %s.", GG_ROOT_CA_PATH ) );
        /* Parse the retrieved JSON to get the GG Core certificate. */
        returnStatus = prvGGDGetIPOnInterface( pcJSONFile,
                                               ulJSONFileLength,
                                               pServerInfo );
    }

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
    TransportInterface_t transportInterface = { 0 };
    /* The network context for the transport layer interface. */
    NetworkContext_t networkContext = { 0 };
    OpensslParams_t opensslParams = { 0 };

    ServerInfo_t xServerInfo = { 0 };

    /* MQTT params.*/
    MQTTStatus_t mqttStatus = MQTTSuccess;
    MQTTContext_t mqttContext = { 0 };
    MQTTFixedBuffer_t mqttBuffer = { 0 };
    bool sessionPresent = false;


    ( void ) argc;
    ( void ) argv;

    /* Set the pParams member of the network context with desired transport. */
    networkContext.pParams = &opensslParams;

    /* Retrieve Greengrass core connection info using an HTTP GET request. */
    returnStatus = retriveGGCoreInfo( &serverInfo );

    /********************* Connect to GG Core ******************************/
    if( returnStatus == EXIT_SUCCESS )
    {
        rootCAFilePath = GG_ROOT_CA_PATH;
        returnStatus = connectToServer( &networkContext );
    }

    /**********************MQTT Operations *********************************/

    /* Define the transport interface and initialize MQTT. */
    if( returnStatus == EXIT_SUCCESS )
    {
        ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
        transportInterface.recv = Openssl_Recv;
        transportInterface.send = Openssl_Send;
        transportInterface.pNetworkContext = &networkContext;

        /* The buffer for MQTT and HTTP can be shared as only one at a time is being used*/
        mqttBuffer.pBuffer = userBuffer;
        mqttBuffer.size = USER_BUFFER_LENGTH;

        /* Initialize MQTT. */
        mqttStatus = MQTT_Init( &mqttContext, &transportInterface, Clock_GetTimeMs, eventCallback, &mqttBuffer );

        if( mqttStatus != MQTTSuccess )
        {
            LogError( ( "MQTT_Init failed with error %d.", mqttStatus ) );
            returnStatus = EXIT_FAILURE;
        }
    }

    /* Establish an MQTT session. */
    if( returnStatus == EXIT_SUCCESS )
    {
        returnStatus = establishMqttSession( &mqttContext, true, &sessionPresent );
    }

    /* Subscribe to response topic. */
    if( returnStatus == EXIT_SUCCESS )
    {
        returnStatus = subscribeToResponseTopic( &mqttContext );
    }

    /* MQTT publish loop. */
    if( returnStatus == EXIT_SUCCESS )
    {
        returnStatus = mqttPublishLoop( &mqttContext );
    }

    /* Disconnect MQTT connection. */
    if( returnStatus == EXIT_SUCCESS )
    {
        mqttStatus = MQTT_Disconnect( &mqttContext );

        if( mqttStatus != MQTTSuccess )
        {
            LogError( ( "MQTT_Disconnect failed with error %d.", mqttStatus ) );
            returnStatus = EXIT_FAILURE;
        }
    }

    /* End TLS session, then close TCP connection. */
    ( void ) Openssl_Disconnect( &networkContext );

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Log message indicating an iteration completed successfully. */
        LogInfo( ( "Demo completed successfully." ) );
    }

    return returnStatus;
}
