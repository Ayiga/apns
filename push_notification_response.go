package apns

// TimeoutSeconds is the maximum number of seconds we're willing to wait for a
// response from the Apple Push Notification Service.
const TimeoutSeconds = 5

// AppleResponseCode represents the various different response codes that can
// be returned by Apple's APN service Binary Provider API.
type AppleResponseCode byte

// The following constants represent response codes potentially returned by
// Apples APNs Binary Provider API.
const (
	// RespNoError represents a non-error
	RespNoError AppleResponseCode = iota

	// RespProcessingError represents an error in processing the request. This
	// is likely an internal error on Apple's APN service part.
	RespProcessingError

	// RespMissingDeviceToken represents an error that indicates that no device
	// token was specified.
	RespMissingDeviceToken

	// RespMissingTopic represents an error that indicates that no topic was
	// specified within the push request.
	RespMissingTopic

	// RespMissingPayload represents an error that indicates that no payload
	// was contained within the push request.  In general this means there was
	// not anything to be pushed to the device.
	RespMissingPayload

	// RespInvalidTokenSize represents an error that indicates a token had an
	// invalid length
	RespInvalidTokenSize

	// RespInvalidTopicSize represents an error that indicates that a topic had
	// an invalid length
	RespInvalidTopicSize

	// RespInvalidPayloadSize represents an erro that indicates that a palyload
	// had an invalid length
	RespInvalidPayloadSize

	// RespInvalidToken represents an error that indicates that the specified
	// token was no valid for a push subscription.  If encountered, you should
	// remove the push subscription token from use.
	RespInvalidToken

	// RespShutdown represents an error that indicates the Apple's APN service
	// has closed this connection, likely used for maintenance.  This does not
	// neccessarily indicate an error with the push itself.
	RespShutdown AppleResponseCode = 10

	// RespUnknown represents an error that indicates an unknown cause.
	RespUnknown AppleResponseCode = 255
)

// ApplePushResponses represents bindings of the AppleResponseCode to various
// messages to use for an error.
//
// This enumerates the response codes that Apple defines
// for push notification attempts.
var ApplePushResponses = map[AppleResponseCode]string{
	RespNoError:            "No errors encountered",
	RespProcessingError:    "An error occurred with processing",
	RespMissingDeviceToken: "The push notification was missing the device token, unable to deliver",
	RespMissingTopic:       "The push notification was missing the topic",
	RespMissingPayload:     "The push notification was missing the payload, nothing to send",
	RespInvalidTokenSize:   "The token was not a valid size for delivery",
	RespInvalidTopicSize:   "The topic was not a valid size for delivery",
	RespInvalidPayloadSize: "The payload was not a valid size for delivery, likely too large",
	RespInvalidToken:       "the token provided was invalid, should be removed",
	RespShutdown:           "The server shutdown the connection.  This most-likely happend for maintenance",
	RespUnknown:            "An unknown error occurred",
}

func (arc AppleResponseCode) Error() string {
	return ApplePushResponses[arc]
}

// PushNotificationResponse details what Apple had to say, if anything.
type PushNotificationResponse struct {
	Success       bool
	AppleResponse AppleResponseCode
	Error         error
}

// NewPushNotificationResponse creates and returns a new PushNotificationResponse
// structure; it defaults to being unsuccessful at first.
func NewPushNotificationResponse() (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)
	resp.Success = false
	return
}
