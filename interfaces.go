package main

import (
	"github.com/aws/aws-sdk-go/service/ecr"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Docker Private Registry interface
type DprInterface interface {
	getAuthToken(server, user, password string) (AuthToken, error)
}

type EcrInterface interface {
	GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

type GcrInterface interface {
	DefaultTokenSource(ctx context.Context, scope ...string) (oauth2.TokenSource, error)
}

type AcrInterface interface {
	getAuthToken(registryURL, clientID, password string) (AuthToken, error)
}
