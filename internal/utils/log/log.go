/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package log

import (
	"fmt"
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

	coloredMsg := time.Now().Format(time.StampMilli) + " " + color + levelStr + message + colorReset
	fmt.Fprintln(output, coloredMsg)
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
