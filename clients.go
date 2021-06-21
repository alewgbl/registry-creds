package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type dprClientData struct{}
type gcrClientData struct{}
type acrClientData struct{}

func newEcrClient() EcrInterface {
	sess := session.Must(session.NewSession())
	awsConfig := aws.NewConfig().WithRegion(*argAWSRegion)

	if *argAWSAssumeRole != "" {
		creds := stscreds.NewCredentials(sess, *argAWSAssumeRole)
		awsConfig.Credentials = creds
	}

	return ecr.New(sess, awsConfig)
}

func newDprClient() DprInterface {
	return dprClientData{}
}

func (dpr dprClientData) getAuthToken(server, user, password string) (AuthToken, error) {
	if server == "" {
		return AuthToken{}, fmt.Errorf("failed to get auth token for docker private registry: empty value for %s", dockerPrivateRegistryServerKey)
	}

	if user == "" {
		return AuthToken{}, fmt.Errorf("failed to get auth token for docker private registry: empty value for %s", dockerPrivateRegistryUserKey)
	}

	if password == "" {
		return AuthToken{}, fmt.Errorf("failed to get auth token for docker private registry: empty value for %s", dockerPrivateRegistryPasswordKey)
	}

	token := base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{user, password}, ":")))

	return AuthToken{AccessToken: token, Endpoint: server}, nil
}

func newGcrClient() GcrInterface {
	return gcrClientData{}
}

func (gcr gcrClientData) DefaultTokenSource(ctx context.Context, scope ...string) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, scope...)
}

func newACRClient() AcrInterface {
	return acrClientData{}
}

func (c acrClientData) getAuthToken(registryURL, clientID, password string) (AuthToken, error) {
	if registryURL == "" {
		return AuthToken{}, fmt.Errorf("azure Container Registry URL is missing; ensure %s parameter is set", acrURLKey)
	}

	if clientID == "" {
		return AuthToken{}, fmt.Errorf("client ID needed to access Azure Container Registry is missing; ensure %s parameter is set", acrClientIDKey)
	}

	if password == "" {
		return AuthToken{}, fmt.Errorf("password needed to access Azure Container Registry is missing; ensure %s paremeter is set", acrClientIDKey)
	}

	token := base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{clientID, password}, ":")))

	return AuthToken{AccessToken: token, Endpoint: registryURL}, nil
}
