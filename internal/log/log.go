package log

import "log"

var currentLogLevel int

func SetLevel(level int) {
	currentLogLevel = level
}

func Debug(format string, v ...interface{}) {
	if currentLogLevel <= 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if currentLogLevel <= 1 {
		log.Printf("[INFO] "+format, v...)
	}
}

func Warn(format string, v ...interface{}) {
	if currentLogLevel <= 2 {
		log.Printf("[WARN] "+format, v...)
	}
}
