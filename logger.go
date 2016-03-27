package apns

import (
	"fmt"
	"log"
	"os"
)

var debugLogger = log.New(os.Stdout, "apns: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)

// DebugAPN is a flag that determins whether or not logging should be output, or
// not
var DebugAPN = false

func vlogf(format string, args ...interface{}) {
	if DebugAPN {
		debugLogger.Output(2, fmt.Sprintf(format, args...))
	}
}
