package fluentstats

import (
	"fmt"
	"io"
	"net"
	"strconv"
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
	//UniqueKey string      `json:"unique_key"`
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
type NoStats struct {
}

// LogToFluentD implements Stats.
func (NoStats) LogToFluentD(record Record, ts time.Time, nodeID string, logName string) {
}

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

// LogToFluentD log info to the fluentd
func (s FluentdStats) LogToFluentD(record Record, ts time.Time, nodeID string, logName string) {
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
	return FluentdStats{
		FluentD: fluentLogger,
	}
}

type ConsoleWriter struct {
	io.Writer
	Out        io.Writer
	TimeFormat string
}
type FluentWriter struct {
	io.Writer
	FluentEnabled bool
	Fluentd       *fluent.Fluent
	NodeID        string
	TimeFormat    string
}

func (fw *FluentWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if fw.FluentEnabled && level > zerolog.TraceLevel {
		err = fw.Fluentd.EncodeAndPostData("bx.go.log", time.Now(), map[string]string{"msg": string(p), "level": level.String(), "instance": fw.NodeID, "timestamp": time.Now().Format(fw.TimeFormat)})
		if err != nil {
			fmt.Println("Error posting to fluentd", err)
			return 0, err
		}
		return len(p), nil
	}

	return len(p), nil
}

func (cw *ConsoleWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level > zerolog.TraceLevel {
		return cw.Out.Write(p)
	}
	return len(p), nil
}
