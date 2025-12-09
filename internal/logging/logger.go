package logging

import "log"

var level int = 1

func SetLevel(l int) { level = l }

func Debug(format string, v ...interface{}) {
	if level <= 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if level <= 1 {
		log.Printf("[INFO] "+format, v...)
	}
}

func Warn(format string, v ...interface{}) {
	if level <= 2 {
		log.Printf("[WARN] "+format, v...)
	}
}
