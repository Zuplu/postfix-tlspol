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

	"golang.org/x/term"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var LogLevels = map[string]LogLevel{
	"debug": DEBUG,
	"info":  INFO,
	"warn":  WARN,
	"error": ERROR,
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorYellow = "\033[93m"
	colorGreen  = "\033[92m"
	colorGrey   = "\033[90m"
)

var minLevel = DEBUG
var logMutex sync.Mutex
var output = os.Stderr
var showTimestamp = false
var showColors = false

func init() {
	_, isJournal := os.LookupEnv("JOURNAL_STREAM")
	_, noColor := os.LookupEnv("NO_COLOR")
	_, noTimestamp := os.LookupEnv("NO_TIMESTAMP")
	isTerminal := term.IsTerminal(int(output.Fd()))
	showTimestamp = !noTimestamp && (!isJournal || isTerminal)
	showColors = !noColor && (isJournal || isTerminal)
}

func logMessage(level LogLevel, message string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	var levelStr string
	var color string
	if level < minLevel {
		return
	}
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

func SetLevel(level LogLevel) {
	minLevel = level
	logMessage(999, fmt.Sprintf("LOG   Set log level to %v", level))
}
