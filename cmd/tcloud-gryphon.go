package cmd

import (
	"net/http"
	"github.com/minio/minio/pkg/auth"
	"fmt"
)

// Decorator to expose AWS Signature V4 verification functions
type AWSV4Verifier struct {
	creds  auth.Credentials
	region string
}

func NewAWSV4Verifier(accessKey string, secretKey string, region string) (*AWSV4Verifier, error) {
	creds, err := auth.CreateCredentials(accessKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("unable create credential, %s", err)
	}

	return &AWSV4Verifier{
		creds: creds,
		region: region,
	}, nil
}

func (verifier AWSV4Verifier) GetCredential() auth.Credentials {
	return verifier.creds
}

func (verifier AWSV4Verifier) IsReqAuthenticated(r *http.Request) (s3Error APIErrorCode) {
	return verifier.isReqAuthenticated(r)
}

func (verifier AWSV4Verifier) CheckAdminRequestAuthType(r *http.Request) APIErrorCode {
	return verifier.checkAdminRequestAuthType(r)
}

func (verifier AWSV4Verifier) GetRegion() string {
	return verifier.region
}
