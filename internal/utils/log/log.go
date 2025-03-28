/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package log

import (
	"fmt"
	"golang.org/x/term"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity of the log message.
type LogLevel int

const (
	// DEBUG level for detailed debug information.
	DEBUG LogLevel = iota
	// INFO level for general informational messages.
	INFO
	// WARN level for warning messages.
	WARN
	// ERROR level for error messages.
	ERROR
)

// color codes for different log levels.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorYellow = "\033[93m"
	colorGreen  = "\033[92m"
	colorGrey   = "\033[90m"
)

// logMutex ensures thread-safe writes to the output
var logMutex sync.Mutex

// output is the writer where logs are written. Defaults to os.Stderr
var output = os.Stderr

var showTimestamp bool = false
var showColors bool = false

func init() {
	_, isJournal := os.LookupEnv("JOURNAL_STREAM")
	_, noColor := os.LookupEnv("NO_COLOR")
	_, noTimestamp := os.LookupEnv("NO_TIMESTAMP")
	isTerminal := term.IsTerminal(int(output.Fd()))
	showTimestamp = !noTimestamp && (!isJournal || isTerminal)
	showColors = !noColor && (isJournal || isTerminal)
}

// logMessage formats and outputs the log message with the appropriate color
func logMessage(level LogLevel, message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	var levelStr string
	var color string

	switch level {
	case DEBUG:
		levelStr = "DEBUG "
		color = colorGrey
	case INFO:
		levelStr = "INFO  "
		color = colorGreen
	case WARN:
		levelStr = "WARN  "
		color = colorYellow
	case ERROR:
		levelStr = "ERROR "
		color = colorRed
	default:
		levelStr = ""
		color = colorReset
	}

	var msg string
	if showTimestamp {
		msg = time.Now().Format(time.StampMilli) + " "
	}
	if showColors {
		msg = msg + color + levelStr + message + colorReset
	} else {
		msg = msg + levelStr + message
	}
	fmt.Fprintln(output, msg)
}

func Debug(v ...interface{}) {
	logMessage(DEBUG, fmt.Sprint(v...))
}

func Debugf(format string, v ...interface{}) {
	logMessage(DEBUG, fmt.Sprintf(format, v...))
}

func Info(v ...interface{}) {
	logMessage(INFO, fmt.Sprint(v...))
}

func Infof(format string, v ...interface{}) {
	logMessage(INFO, fmt.Sprintf(format, v...))
}

func Warn(v ...interface{}) {
	logMessage(WARN, fmt.Sprint(v...))
}

func Warnf(format string, v ...interface{}) {
	logMessage(WARN, fmt.Sprintf(format, v...))
}

func Error(v ...interface{}) {
	logMessage(ERROR, fmt.Sprint(v...))
}

func Errorf(format string, v ...interface{}) {
	logMessage(ERROR, fmt.Sprintf(format, v...))
}
