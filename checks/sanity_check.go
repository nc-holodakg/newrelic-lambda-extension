package checks

import (
	"context"
	"fmt"

	"github.com/newrelic/newrelic-lambda-extension/config"
	"github.com/newrelic/newrelic-lambda-extension/credentials"
	"github.com/newrelic/newrelic-lambda-extension/lambda/extension/api"
	"github.com/newrelic/newrelic-lambda-extension/util"
)

var (
	awsLogIngestionEnvVars = []string{
		"DEBUG_LOGGING_ENABLED",
		"INFRA_ENABLED",
		"LICENSE_KEY",
		"LOGGING_ENABLED",
		"NR_INFRA_ENDPOINT",
		"NR_LOGGING_ENDPOINT",
	}
)

// sanityCheck checks for configuration that is either misplaced or in conflict
func sanityCheck(ctx context.Context, conf *config.Configuration, res *api.RegistrationResponse, _ runtimeConfig) error {
	if util.AnyEnvVarsExist(awsLogIngestionEnvVars) {
		return fmt.Errorf("Environment variable '%s' is used by aws-log-ingestion and has no effect here. Recommend unsetting this environment variable within this function.", util.AnyEnvVarsExistString(awsLogIngestionEnvVars))
	}

	envKeyExists := util.EnvVarExists("NEW_RELIC_LICENSE_KEY")
	isSecretConfigured := credentials.IsSecretConfigured(ctx, conf)
	isParameterConfigured := credentials.IsParameterConfigured(ctx, conf)

	if isSecretConfigured && envKeyExists {
		return fmt.Errorf("There is both a AWS Secrets Manager secret and a NEW_RELIC_LICENSE_KEY environment variable set. Recommend removing the NEW_RELIC_LICENSE_KEY environment variable and using the AWS Secrets Manager secret.")
	}

	if isParameterConfigured && envKeyExists {
		return fmt.Errorf("There is both a AWS Parameter Store parameter and a NEW_RELIC_LICENSE_KEY environment variable set. Recommend removing the NEW_RELIC_LICENSE_KEY environment variable and using the AWS Parameter Store parameter.")
	}

	if isSecretConfigured && isParameterConfigured {
		return fmt.Errorf("There is both a AWS Secrets Manager secret and a AWS Parameter Store parameter set. Recommend using just one.")
	}

	return nil
}
