package cloudwatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
)

const (
	DefaultCloudWatchLogsRegion = "eu-west-1"
	DefaultLogGroupName         = "/org/vault/audit"
)

func tokenHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func Factory(ctx context.Context, conf *audit.BackendConfig) (audit.Backend, error) {
	if conf.SaltConfig == nil {
		return nil, fmt.Errorf("nil salt config")
	}
	if conf.SaltView == nil {
		return nil, fmt.Errorf("nil salt view")
	}

	// We assume the Log Group has been previously created.
	regionName, ok := conf.Config["region_name"]
	if !ok {
		regionName = DefaultCloudWatchLogsRegion
	}

	awsConf := aws.NewConfig().WithRegion(regionName)
	awsSession, err := session.NewSession(awsConf)
	if err != nil {
		return nil, fmt.Errorf("could not establish AWS session: %q", err)
	}

	cloudWatchLogs := cloudwatchlogs.New(awsSession)

	// We assume the Log Group has been previously created.
	logGroupName, ok := conf.Config["log_group_name"]
	if !ok {
		logGroupName = DefaultLogGroupName
	}

	logStreamName, ok := conf.Config["log_stream_name"]
	if !ok {
		uid, _ := tokenHex(16)
		logStreamName = fmt.Sprintf("%s/[$LATEST]%s", time.Now().Format("2006/01/02"), uid)
	}

	logStreamInput := cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(logGroupName),
		LogStreamName: aws.String(logStreamName),
	}

	_, err = cloudWatchLogs.CreateLogStream(&logStreamInput)
	if err != nil {
		return nil, fmt.Errorf("could not create log stream: %q", err)
	}

	// Check if hashing of accessor is disabled
	hmacAccessor := true
	if hmacAccessorRaw, ok := conf.Config["hmac_accessor"]; ok {
		value, err := strconv.ParseBool(hmacAccessorRaw)
		if err != nil {
			return nil, err
		}
		hmacAccessor = value
	}

	// Check if raw logging is enabled
	logRaw := false
	if raw, ok := conf.Config["log_raw"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		logRaw = b
	}

	b := &Backend{
		client:        cloudWatchLogs,
		logGroupName:  logGroupName,
		logStreamName: logStreamName,
		saltConfig:    conf.SaltConfig,
		saltView:      conf.SaltView,
		formatConfig: audit.FormatterConfig{
			Raw:          logRaw,
			HMACAccessor: hmacAccessor,
		},
	}

	b.formatter.AuditFormatWriter = &audit.JSONFormatWriter{
		Prefix:   conf.Config["prefix"],
		SaltFunc: b.Salt,
	}

	return b, nil
}

// Backend is the audit backend for the CloudWatch Logs-based audit store.
type Backend struct {
	client             *cloudwatchlogs.CloudWatchLogs
	logGroupName       string
	logStreamName      string
	sequenceTokenMutex sync.Mutex
	sequenceToken      string

	formatter    audit.AuditFormatter
	formatConfig audit.FormatterConfig

	saltMutex  sync.RWMutex
	salt       *salt.Salt
	saltConfig *salt.Config
	saltView   logical.Storage
}

var _ audit.Backend = (*Backend)(nil)

func (b *Backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.saltView, b.saltConfig)
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return salt, nil
}

func (b *Backend) GetHash(ctx context.Context, data string) (string, error) {
	salt, err := b.Salt(ctx)
	if err != nil {
		return "", err
	}
	return audit.HashString(salt, data), nil
}

func (b *Backend) LogRequest(ctx context.Context, in *audit.LogInput) error {
	b.sequenceTokenMutex.Lock()
	defer b.sequenceTokenMutex.Unlock()

	var buf bytes.Buffer
	if err := b.formatter.FormatRequest(ctx, &buf, b.formatConfig, in); err != nil {
		return err
	}

	message := string(buf.Bytes())
	ts := time.Now().Unix() * 1000
	content := cloudwatchlogs.InputLogEvent{
		Message:   &message,
		Timestamp: &ts,
	}
	events := []*cloudwatchlogs.InputLogEvent{&content}
	logEvent := cloudwatchlogs.PutLogEventsInput{
		LogEvents:     events,
		LogGroupName:  aws.String(b.logGroupName),
		LogStreamName: aws.String(b.logStreamName),
	}
	if b.sequenceToken != "" {
		logEvent.SequenceToken = aws.String(b.sequenceToken)
	}
	response, err := b.client.PutLogEvents(&logEvent)
	if err != nil {
		return err
	}
	b.sequenceToken = *response.NextSequenceToken

	return nil
}

func (b *Backend) LogResponse(ctx context.Context, in *audit.LogInput) error {
	b.sequenceTokenMutex.Lock()
	defer b.sequenceTokenMutex.Unlock()

	var buf bytes.Buffer
	if err := b.formatter.FormatResponse(ctx, &buf, b.formatConfig, in); err != nil {
		return err
	}

	message := string(buf.Bytes())
	ts := time.Now().Unix() * 1000
	content := cloudwatchlogs.InputLogEvent{
		Message:   &message,
		Timestamp: &ts,
	}
	events := []*cloudwatchlogs.InputLogEvent{&content}
	logEvent := cloudwatchlogs.PutLogEventsInput{
		LogEvents:     events,
		LogGroupName:  aws.String(b.logGroupName),
		LogStreamName: aws.String(b.logStreamName),
	}
	if b.sequenceToken != "" {
		logEvent.SequenceToken = aws.String(b.sequenceToken)
	}
	response, err := b.client.PutLogEvents(&logEvent)
	if err != nil {
		return err
	}
	b.sequenceToken = *response.NextSequenceToken

	return nil
}

func (b *Backend) Reload(_ context.Context) error {
	// Should establish new CloudWatch Logs client

	return nil
}

func (b *Backend) Invalidate(_ context.Context) {
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	b.salt = nil
}
