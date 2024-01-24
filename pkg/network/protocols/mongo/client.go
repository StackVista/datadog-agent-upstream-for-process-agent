// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package mongo

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/DataDog/datadog-agent/pkg/util/common"
)

const (
	defaultConnectionTimeout = time.Second * 10
)

type Options struct {
	ClientDialer     *net.Dialer
	ServerAddress    string
	Username         string
	Password         string
	ConnectionTimout time.Duration
}

type Client struct {
	C *mongo.Client
}

func NewClientWithClientOptions(clientOptions *options.ClientOptions, timeout time.Duration) (*Client, error) {
	timedCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := mongo.Connect(timedCtx, clientOptions)
	if err != nil {
		return nil, err
	}

	timedCtx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := client.Ping(timedCtx, nil); err != nil {
		return nil, err
	}

	return &Client{
		C: client,
	}, nil

}

func NewClient(opts Options) (*Client, error) {
	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", opts.ServerAddress))
	if opts.Username == "" {
		opts.Username = "user"
	}
	if opts.Password == "" {
		opts.Password = "pass"
	}
	creds := options.Credential{
		Username:   opts.Username,
		Password:   opts.Password,
		AuthSource: "admin",
	}
	clientOptions.SetAuth(creds)
	clientOptions.SetDirect(true)

	if opts.ConnectionTimout == 0 {
		opts.ConnectionTimout = defaultConnectionTimeout
	}

	if opts.ClientDialer != nil {
		clientOptions.SetDialer(opts.ClientDialer)
	}

	return NewClientWithClientOptions(clientOptions, opts.ConnectionTimout)
}

var (
	defaultDBs = common.StringSet{
		"admin":  {},
		"config": {},
		"local":  {},
	}
)

// Do some work on the database to generate some stats
// You will generally not care about the result of this function
func (c *Client) GenerateLoad() error {
	c.C.ListDatabases(context.Background(), bson.M{})
	usersCollection := c.C.Database("testing").Collection("users")
	user := bson.D{{"fullName", "John Doe"}, {"age", 30}}
	_, err := usersCollection.InsertOne(context.Background(), user)
	return err
}

func (c *Client) DeleteDatabases() error {
	dbs, err := c.C.ListDatabases(context.Background(), bson.M{})
	if err != nil {
		return err
	}

	for _, db := range dbs.Databases {
		if _, isDefault := defaultDBs[db.Name]; isDefault {
			continue
		}
		if err := c.C.Database(db.Name).Drop(context.Background()); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) Stop() error {
	return c.C.Disconnect(context.Background())
}
