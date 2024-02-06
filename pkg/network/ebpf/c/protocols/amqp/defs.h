#ifndef __AMQP_DEFS_H
#define __AMQP_DEFS_H

// For protocol detection.
#define AMQP_PREFACE "AMQP"

// RabbitMQ supported classes.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
#define AMQP_CONNECTION_CLASS 10
#define AMQP_BASIC_CLASS 60

// RabbitMQ supported methods types for the basic class.
#define AMQP_METHOD_PUBLISH 40
#define AMQP_METHOD_DELIVER 60
#define AMQP_METHOD_GET_OK 71

// RabbitMQ supported methods for the connection class.
#define AMQP_METHOD_CONNECTION_CLOSE 50

// Since the AMQP transction entries contain the exchange name or routing key,
// each indiviual batch entry is rather large, so the batch has to be smaller.
#define AMQP_BATCH_SIZE 13

#endif
