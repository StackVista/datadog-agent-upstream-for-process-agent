#ifndef __AMQP_DEFS_H
#define __AMQP_DEFS_H

#define AMQP_PREFACE "AMQP"

// RabbitMQ supported classes.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
#define AMQP_CONNECTION_CLASS 10
#define AMQP_BASIC_CLASS 60
#define AMQP_CHANNEL_CLASS 20

#define AMQP_METHOD_CLOSE_OK 40
#define AMQP_METHOD_CLOSE 41

// RabbitMQ supported connections.
#define AMQP_METHOD_CONNECTION_START 10
#define AMQP_METHOD_CONNECTION_START_OK 11

// RabbitMQ supported methods types.
#define AMQP_METHOD_CONSUME 20
#define AMQP_METHOD_PUBLISH 40
#define AMQP_METHOD_DELIVER 60

// Enough to get to the frame size.
#define AMQP_MIN_FRAME_LENGTH 8
#define AMQP_MIN_PAYLOAD_LENGTH 11

// Since the AMQP tranaction entries contain the exchange name and routing key,
// each indiviual batch entry is rather larget (> 512 bytes), so the batch has to be
// smaller.
#define AMQP_BATCH_SIZE 5

#endif
