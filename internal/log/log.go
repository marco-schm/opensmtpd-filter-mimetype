package log

import "log"

type Logger struct {
	level int
}

func New(level int) *Logger {
	return &Logger{level: level}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level <= 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level <= 1 {
		log.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level <= 2 {
		log.Printf("[WARN] "+format, v...)
	}
}
