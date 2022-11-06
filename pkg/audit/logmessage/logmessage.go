package logmessage

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/hupe1980/awsrecon/pkg/audit/secret"
)

type Engine struct {
	secretEngine *secret.Engine
}

func NewEngine(verify bool) *Engine {
	return &Engine{
		secretEngine: secret.NewEngine(verify),
	}
}

type Result struct {
	Count int
	Hints []string
}

type ResultMap = map[string]*Result

func (e *Engine) Scan(events []types.FilteredLogEvent) ResultMap {
	resultMap := make(map[string]*Result)

	for _, event := range events {
		message := aws.ToString(event.Message)

		if isDefaultLog(message) {
			continue
		}

		logstreamName := aws.ToString(event.LogStreamName)

		if _, ok := resultMap[logstreamName]; !ok {
			resultMap[logstreamName] = new(Result)
		}

		hints := e.secretEngine.Scan(message)

		result := resultMap[logstreamName]

		result.Hints = append(result.Hints, hints...)
		result.Count = result.Count + 1
	}

	return resultMap
}

func isDefaultLog(message string) bool {
	if strings.HasPrefix(message, "START RequestId:") {
		return true
	}

	if strings.HasPrefix(message, "END RequestId:") {
		return true
	}

	if strings.HasPrefix(message, "REPORT RequestId:") {
		return true
	}

	return false
}
