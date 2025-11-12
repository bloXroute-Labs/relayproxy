package fluentstats

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/rs/zerolog"
)

const (
	// DateFormat is an example to date time string format
	DateFormat = "2006-01-02T15:04:05.000000"
)

// Record represents a bloxroute style stat type record
type Record struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// LogRecord represents a log message to be sent to FluentD
type LogRecord struct {
	Level     string `json:"level"`
	Name      string `json:"name"`
	Msg       Record `json:"msg"`
	Instance  string `json:"instance"`
	Timestamp string `json:"timestamp"`
}

// Stats is used to generate STATS records
type Stats interface {
	LogToFluentD(record Record, ts time.Time, nodeID string, logName string)
}

// NoStats is used to generate empty stats
type NoStats struct{}

// LogToFluentD implements Stats.
func (NoStats) LogToFluentD(record Record, ts time.Time, nodeID string, logName string) {}

// FluentdStats struct that represents fluentd stats info
type FluentdStats struct {
	FluentD *fluent.Fluent
}

// NewStats is used to create transaction STATS logger
func NewStats(fluentDEnabled bool, fluentDHost string) Stats {
	if !fluentDEnabled {
		return NoStats{}
	}
	return newStats(fluentDHost)
}

// LogToFluentD logs info to FluentD
func (s FluentdStats) LogToFluentD(record Record, ts time.Time, nodeID string, logName string) {
	if s.FluentD == nil {
		return
	}
	d := LogRecord{
		Level:     "STATS",
		Name:      logName,
		Msg:       record,
		Instance:  nodeID,
		Timestamp: ts.Format(DateFormat),
	}

	err := s.FluentD.EncodeAndPostData("bx.eth.builder.go.log", ts, d)
	if err != nil {
		log.Error("Error sending message to fluentD", "err", err)
	}
}

func newStats(fluentdHost string) Stats {
	host, port, err := net.SplitHostPort(fluentdHost)
	if err != nil {
		log.Error("Error parsing fluentd host", "err", err)
		return NoStats{}
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		log.Error("Error parsing port to integer", "err", err)
		return NoStats{}
	}
	fluentLogger, err := fluent.New(fluent.Config{
		FluentHost:    host,
		FluentPort:    portInt,
		MarshalAsJSON: true,
		Async:         true,
	})
	log.Info("Connecting to fluentd", "host", host, "port", portInt)
	if err != nil {
		log.Error("Error connecting to fluentd", "err", err)
		return NoStats{}
	}
	return FluentdStats{FluentD: fluentLogger}
}

type ConsoleWriter struct {
	Out        io.Writer
	TimeFormat string
}

func (cw *ConsoleWriter) Write(p []byte) (int, error) {
	return cw.WriteLevel(zerolog.InfoLevel, p)
}

func (cw *ConsoleWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if cw == nil || cw.Out == nil {
		return len(p), nil
	}
	if level > zerolog.TraceLevel {
		return cw.Out.Write(p)
	}
	return len(p), nil
}

type FluentWriter struct {
	FluentEnabled bool
	Fluentd       *fluent.Fluent
	NodeID        string
	TimeFormat    string

	closed atomic.Bool
}

func (fw *FluentWriter) Close() error {
	if fw == nil {
		return nil
	}
	if fw.closed.Swap(true) {
		return nil
	}
	if fw.Fluentd != nil {
		_ = fw.Fluentd.Close()
	}
	return nil
}

// Write is used when zerolog/diode or MultiLevelWriter only has io.Writer.
func (fw *FluentWriter) Write(p []byte) (int, error) {
	return fw.WriteLevel(zerolog.InfoLevel, p)
}

func (fw *FluentWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	defer func() { _ = recover() }()

	// Drop quietly if disabled/closed/not configured
	if fw == nil || fw.closed.Load() || !fw.FluentEnabled || fw.Fluentd == nil {
		return len(p), nil
	}
	if level <= zerolog.TraceLevel {
		return len(p), nil
	}

	now := time.Now()
	if e := fw.Fluentd.EncodeAndPostData(
		"bx.go.log",
		now,
		map[string]string{
			"msg":       string(p),
			"level":     level.String(),
			"instance":  fw.NodeID,
			"timestamp": now.Format(fw.TimeFormat),
		},
	); e != nil {
		fmt.Println("Error posting to fluentd", e)
		return len(p), nil
	}
	return len(p), nil
}
