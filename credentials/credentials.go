package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/newrelic/newrelic-lambda-extension/util"

	"github.com/newrelic/newrelic-lambda-extension/config"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

type licenseKeySecret struct {
	LicenseKey string
}

var (
	sess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	secrets   secretsmanageriface.SecretsManagerAPI
	ssmClient ssmiface.SSMAPI
)

const defaultSecretId = "NEW_RELIC_LICENSE_KEY"

func init() {
	secrets = secretsmanager.New(sess)
	ssmClient = ssm.New(sess)
}

func getLicenseKeySecretId(conf *config.Configuration) string {
	if conf.LicenseKeySecretId != "" {
		util.Logln("Fetching license key from secret id " + conf.LicenseKeySecretId)
		return conf.LicenseKeySecretId
	}

	return ""
}

func getLicenseKeyParameterName(conf *config.Configuration) string {
	if conf.LicenseKeyParameterName != "" {
		util.Logln("Fetching license key from parameter name " + conf.LicenseKeyParameterName)
		return conf.LicenseKeyParameterName
	}

	return ""
}

func decodeLicenseKey(rawJson *string) (string, error) {
	var secrets licenseKeySecret

	err := json.Unmarshal([]byte(*rawJson), &secrets)
	if err != nil {
		return "", err
	}
	if secrets.LicenseKey == "" {
		return "", fmt.Errorf("malformed license key secret; missing \"LicenseKey\" attribute")
	}

	return secrets.LicenseKey, nil
}

// IsSecretConfigured returns true if the Secrets Maanger secret is configured, false
// otherwise
func IsSecretConfigured(ctx context.Context, conf *config.Configuration) bool {
	secretId := getLicenseKeySecretId(conf)
	if secretId == "" {
		return false
	}

	secretValueInput := secretsmanager.GetSecretValueInput{SecretId: &secretId}

	_, err := secrets.GetSecretValueWithContext(ctx, &secretValueInput)
	if err != nil {
		return false
	}

	return true
}

// IsParameterConfigured returns true if the SSM parameter is configured, false
// otherwise.
func IsParameterConfigured(ctx context.Context, conf *config.Configuration) bool {
	parameterName := getLicenseKeyParameterName(conf)
	if parameterName == "" {
		return false
	}

	_, err := tryLicenseKeyFromParameter(ctx, parameterName)
	if err != nil {
		return false
	}

	return true
}

// GetNewRelicLicenseKey fetches the license key from AWS Secrets Manager, falling back
// to the NEW_RELIC_LICENSE_KEY environment variable if set.
func GetNewRelicLicenseKey(ctx context.Context, conf *config.Configuration) (string, error) {
	if conf.LicenseKey != "" {
		util.Logln("Using license key from environment variable")
		return conf.LicenseKey, nil
	}

	var err error
	var licenseKey string

	secretId := getLicenseKeySecretId(conf)
	if secretId != "" {
		licenseKey, err = tryLicenseKeyFromSecret(ctx, secretId)
		if err == nil {
			return licenseKey, nil
		}
	}

	parameterName := getLicenseKeyParameterName(conf)
	if parameterName != "" {
		licenseKey, err = tryLicenseKeyFromParameter(ctx, parameterName)
		if err == nil {
			return licenseKey, nil
		}
	}

	envLicenseKey, found := os.LookupEnv(defaultSecretId)
	if found {
		return envLicenseKey, nil
	}

	// Check for errors while fetching from Secrets Manager or SSM Parameter Store
	if err != nil {
		return "", err
	}

	util.Logln("No configured license key found, attempting fallbacks")

	licenseKey, err = tryLicenseKeyFromSecret(ctx, defaultSecretId)
	if err == nil {
		return licenseKey, nil
	}

	licenseKey, err = tryLicenseKeyFromParameter(ctx, defaultSecretId)
	if err == nil {
		return licenseKey, nil
	}

	return "", fmt.Errorf("No license key configured")
}

func tryLicenseKeyFromSecret(ctx context.Context, secretId string) (string, error) {
	util.Debugf("fetching '%s' from Secrets Manager\n", secretId)

	secretValueInput := secretsmanager.GetSecretValueInput{SecretId: &secretId}

	secretValueOutput, err := secrets.GetSecretValueWithContext(ctx, &secretValueInput)
	if err != nil {
		return "", err
	}

	return decodeLicenseKey(secretValueOutput.SecretString)
}

func tryLicenseKeyFromParameter(ctx context.Context, parameterName string) (string, error) {
	util.Debugf("fetching '%s' from SSM Parameter Store\n", parameterName)

	parameterValueInput := ssm.GetParameterInput{Name: &parameterName, WithDecryption: aws.Bool(true)}

	parameterValueOutput, err := ssmClient.GetParameterWithContext(ctx, &parameterValueInput)
	if err != nil {
		return "", err
	}

	return *parameterValueOutput.Parameter.Value, nil
}

// OverrideSecretsManager overrides the default Secrets Manager implementation
func OverrideSecretsManager(override secretsmanageriface.SecretsManagerAPI) {
	secrets = override
}

// OverrideSSM overrides the default SSM implementation
func OverrideSSM(override ssmiface.SSMAPI) {
	ssmClient = override
}
