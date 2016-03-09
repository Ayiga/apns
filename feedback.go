package apns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// the binary provider api tends to be of the following format, url wise:
//
// feedback.push.apple.com:2196
// feedback.sandbox.push.apple.com:2196

// FeedbackTimeoutSeconds specifies how long to wait for a response from Apple's
// APNs service before returning a response.  This is done as Apple will not
// send a response on their Binary Provider API if everything is successful.
// Ultimately this means that a response is not guaranteed.
const FeedbackTimeoutSeconds = 5

// FeedbackChannel will receive individual responses from Apple.
var FeedbackChannel = make(chan (*FeedbackResponse))

// ShutdownChannel is a signal channel the informs us there's nothing to read.
// It will receive a true, if that is the case.
var ShutdownChannel = make(chan bool)

// FeedbackResponse represents a device token that Apple has
// indicated should not be sent to in the future.
type FeedbackResponse struct {
	Timestamp   uint32
	DeviceToken string
}

// NewFeedbackResponse creates and returns a FeedbackResponse structure.
func NewFeedbackResponse() (resp *FeedbackResponse) {
	resp = new(FeedbackResponse)
	return
}

// ListenForFeedback connects to the Apple Feedback Service
// and checks for device tokens.
//
// Feedback consists of device tokens that should
// not be sent to in the future; Apple *does* monitor that
// you respect this so you should be checking it ;)
func (client *GatewayClient) ListenForFeedback() (err error) {
	tlsConn, err := client.getConn()
	if err != nil {
		return err
	}

	var tokenLength uint16
	buffer := make([]byte, 38, 38)
	deviceToken := make([]byte, 32, 32)

	for {
		_, err := tlsConn.Read(buffer)
		if err != nil {
			ShutdownChannel <- true
			break
		}

		resp := NewFeedbackResponse()

		r := bytes.NewReader(buffer)
		binary.Read(r, binary.BigEndian, &resp.Timestamp)
		binary.Read(r, binary.BigEndian, &tokenLength)
		binary.Read(r, binary.BigEndian, &deviceToken)
		if tokenLength != 32 {
			return errors.New("token length should be equal to 32, but isn't")
		}
		resp.DeviceToken = hex.EncodeToString(deviceToken)

		FeedbackChannel <- resp
	}

	return nil
}
