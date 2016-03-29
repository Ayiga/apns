package apns

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// statusCode represents status codes that are returned from the Request result
type statusCode int

// ErrMaxRetriesExceeded represents an error that states that the push was
// attempted to be sent, and was unsuccessful up to the alloted retry count
var ErrMaxRetriesExceeded = errors.New("Tried to send the push, and failed beyodn the maximum retry count")

const (
	// CodeSuccess represents that everything's ok
	CodeSuccess statusCode = 200

	// CodeBadRequest represents that the request was not completeled
	// successfully
	CodeBadRequest statusCode = 400

	// CodeCertificateError represents an error while validating the certificate
	// used to communicate with the service.
	CodeCertificateError statusCode = 403

	// CodeBadMethod represents an error for using the wrong method, in this
	// case it means something other than POST was used.
	CodeBadMethod statusCode = 405

	// CodeInactiveDeviceToken represents a code that indicates that the device
	// toekn should no longer be used.
	CodeInactiveDeviceToken statusCode = 410

	// CodePayloadTooLarge represents an error that states the Payload was too
	// big to be used.
	CodePayloadTooLarge statusCode = 413

	// CodeTooManyRequestsForDeviceToken represents an error that indicates that
	// too many push requests have been sent to the same device within too short
	// of a time frame.
	CodeTooManyRequestsForDeviceToken statusCode = 429

	// CodeInternalServerError represents an error that indicates an internal
	// server error has ocurred.
	CodeInternalServerError statusCode = 500

	// CodeServerShutdown represents a status that indicates the server will be
	// shutting down, and so the connection should be closed.
	CodeServerShutdown statusCode = 503
)

var statusCodeReasons = map[statusCode]string{
	CodeSuccess:                       "Request succeeded",
	CodeBadMethod:                     "The request method is incorrect, it should be POST",
	CodeBadRequest:                    "The request was bad",
	CodeCertificateError:              "The Certificate provided had an issue",
	CodeServerShutdown:                "The Server will be shutting down",
	CodeInactiveDeviceToken:           "The device token specified is no longer active",
	CodeInternalServerError:           "An internal server error occurred while processing the request",
	CodePayloadTooLarge:               "The payload sent was too large to be processed",
	CodeTooManyRequestsForDeviceToken: "Too many requests were received for the given Device Token",
}

// Error implements the error interface
func (s statusCode) Error() string {
	return statusCodeReasons[s]
}

// APIReason represents the potential reasons returned for an API Request result
type APIReason string

const (
	// ReasonPayloadEmpty represents a reason for error due to a payload empty
	ReasonPayloadEmpty APIReason = "PayloadEmpty"

	// ReasonPayloadTooLarge represents a resason that the payload exceeded the
	// maximum size of 4096 bytes
	ReasonPayloadTooLarge APIReason = "PayloadTooLarge"

	// ReasonBadTopic represents a resason that the topic was either not
	// specified
	ReasonBadTopic APIReason = "BadTopic"

	//ReasonTopicDisallowed represents a reason that the specified topic is not
	//allowed
	ReasonTopicDisallowed APIReason = "TopicDisallowed"

	// ReasonBadMessageID represents a reason that the message id specified is
	// bad
	ReasonBadMessageID APIReason = "BadMessageId"

	// ReasonBadExpirationDate represents a reason that the specified expiration
	// date is not a good one.
	ReasonBadExpirationDate APIReason = "BadExpirationDate"

	// ReasonBadPriority represents a reason that specifies that the priority
	// specified was not valid given the rest of the notification, or just an
	// invalid number
	ReasonBadPriority APIReason = "BadPriority"

	// ReasonMissingDeviceToken represents a reason that specifies that the
	// device token was not specified, and therefore no push could be delivered
	ReasonMissingDeviceToken APIReason = "MissingDeviceToken"

	// ReasonBadDeviceToken represents a reason that specifies that the device
	// Toekn is not a valid one.
	ReasonBadDeviceToken APIReason = "BadDeviceToken"

	// ReasonDeviceTokenNotForTopic represents a reason that specifies that the
	// specified device token hasn't subscribed for push subscriptions for the
	// given topic.
	ReasonDeviceTokenNotForTopic APIReason = "DeviceTokenNotForTopic"

	// ReasonUnregistered represetns a reason that specifies that the device
	// token has unregistered for notifications for the given topic.
	ReasonUnregistered APIReason = "ReasonUnregistered"

	// ReasonDuplicateHeaders represents a reason that specifies that one or
	// more headers were repeated.
	ReasonDuplicateHeaders APIReason = "DuplicateHeaders"

	// ReasonBadCertificateEnvironment represents a reason that indicates that
	// the certificate supplied does not match the request environment.
	ReasonBadCertificateEnvironment APIReason = "BadCertificateEnvironment"

	// ReasonBadCertificate represents a reason that the certificate specified
	// is not a valid certificate.
	ReasonBadCertificate APIReason = "BadCertificate"

	// ReasonForbidden represents a reason that specifies that the action
	// requested is not valid.
	ReasonForbidden APIReason = "Forbidden"

	// ReasonBadPath represents a reason that specifies that the path specified
	// is not a good one.
	ReasonBadPath APIReason = "BadPath"

	// ReasonMethodNotAllowed represents a reason that specifies that the
	// request method is not allowed.  The only one allowed, currently is POST.
	ReasonMethodNotAllowed APIReason = "MethodNotAllowed"

	// ReasonTooManyRequests represents a reason that indicates that too many
	// requests have been made to the same device token.
	ReasonTooManyRequests APIReason = "TooManyRequests"

	// ReasonIdleTimeout represents a reason that the given connection has timed
	// out after being idle for too long.
	ReasonIdleTimeout APIReason = "IdleTimeout"

	// ReasonShutdown represents a reason that the APN service is shutting down
	// and the connections are to be terminated.
	ReasonShutdown APIReason = "Shutdown"

	// ReasonInternalServerError represents a reason that indicates that the
	// APN service encountered an internal error while processing your request.
	ReasonInternalServerError APIReason = "InternalServerError"

	// ReasonServiceUnavailable represents a reason that indicates that the
	// APN Service is unavailable.
	ReasonServiceUnavailable APIReason = "ServiceUnavailable"

	// ReasonMissingTopic represents a reason that indicates that the topic is
	// missing from the Notification, and cannot be inferred from the
	// certificate.
	ReasonMissingTopic APIReason = "MissingTopic"
)

var apiReasons = map[APIReason]string{
	ReasonPayloadEmpty:              "The message payload was empty.",
	ReasonPayloadTooLarge:           "The message payload was too large. The maximum payload size is 4096 bytes.",
	ReasonBadTopic:                  "The apns-topic was invalid.",
	ReasonTopicDisallowed:           "Pushing to this topic is not allowed.",
	ReasonBadMessageID:              "The apns-id value is bad.",
	ReasonBadExpirationDate:         "The apns-expiration value is bad.",
	ReasonBadPriority:               "The apns-priority value is bad.",
	ReasonMissingDeviceToken:        "The device token is not specified in the request :path. Verify that the :path header contains the device token.",
	ReasonBadDeviceToken:            "The specified device token was bad. Verify that the request contains a valid token and that the token matches the environment.",
	ReasonDeviceTokenNotForTopic:    "The device token does not match the specified topic.",
	ReasonUnregistered:              "The device token is inactive for the specified topic.",
	ReasonDuplicateHeaders:          "One or more headers were repeated.",
	ReasonBadCertificateEnvironment: "The client certificate was for the wrong environment.",
	ReasonBadCertificate:            "The certificate was bad.",
	ReasonForbidden:                 "The specified action is not allowed.",
	ReasonBadPath:                   "The request contained a bad :path value.",
	ReasonMethodNotAllowed:          "The specified :method was not POST.",
	ReasonTooManyRequests:           "Too many requests were made consecutively to the same device token.",
	ReasonIdleTimeout:               "Idle time out.",
	ReasonShutdown:                  "The server is shutting down.",
	ReasonInternalServerError:       "An internal server error occurred.",
	ReasonServiceUnavailable:        "The service is unavailable.",
	ReasonMissingTopic:              "The apns-topic header of the request was not specified and was required. The apns-topic header is mandatory when the client is connected using a certificate that supports multiple topics.",
}

func (a APIReason) Error() string {
	return apiReasons[a]
}

// APIResponse represents a potential resposne from the APN services's HTTP2
// APNs Provider API
type APIResponse struct {

	// Reason represents the reason, this will be populated with the reason for
	// the failure
	Reason APIReason `json:"reason"`

	// Timestamp is used for status code 410, and indicates the last time the
	// specified device token was valid for the topic.  This is a unix timestamp
	// represented in milli seconds
	Timestamp int64 `json:"timestamp,omitempty"`
}

// ToTime will take the underlying timestamp and convert it to to a timestamp,
// in Unix time since Epoc 0.
func (r APIResponse) ToTime() time.Time {
	secs := (r.Timestamp / 1000)
	nsecs := (r.Timestamp % 1000) * 1000000
	return time.Unix(secs, nsecs)
}

// HTTP2Client contains the fields necessary to communicate
// with Apple, such as the gateway to use and your
// certificate contents.
//
// You'll need to provide your own certificateFile
// and keyFile to send notifications. Ideally, you'll
// just set the certificateFile and keyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the certificateBase64
// and keyBase64 fields to store the actual contents.
type HTTP2Client struct {
	gateway           *url.URL
	certificateFile   string
	certificateBase64 string
	keyFile           string
	keyBase64         string
}

// the HTTP2 APNs Provider API tends to be of the following format, url wise:
// api.development.push.apple.com:2197
// api.push.apple.com:2197
// api.development.push.apple.com:443
// api.push.apple.com:443

// BareHTTP2Client can be used to set the contents of your
// certificate and key blocks manually.
func BareHTTP2Client(gateway, certificateBase64, keyBase64 string) (c Client) {
	uri, err := getURL(gateway)
	if err != nil {
		return nil
	}

	client := &HTTP2Client{
		gateway:           uri,
		certificateBase64: certificateBase64,
		keyBase64:         keyBase64,
	}

	return client
}

// NewHTTP2Client assumes you'll be passing in paths that
// point to your certificate and key.
func NewHTTP2Client(gateway, certificateFile, keyFile string) (c Client) {
	uri, err := getURL(gateway)
	if err != nil {
		return nil
	}

	client := &HTTP2Client{
		gateway:         uri,
		certificateFile: certificateFile,
		keyFile:         keyFile,
	}

	return client
}

const apiMaxRetryCount = 4

// Send implements Client
func (client *HTTP2Client) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	for i := 0; i < apiMaxRetryCount; i++ {

		var cert tls.Certificate
		var err error
		if len(client.certificateBase64) == 0 && len(client.keyBase64) == 0 {
			// The user did not specify raw block contents, so check the filesystem.
			cert, err = tls.LoadX509KeyPair(client.certificateFile, client.keyFile)
		} else {
			// The user provided the raw block contents, so use that.
			cert, err = tls.X509KeyPair([]byte(client.certificateBase64), []byte(client.keyBase64))
		}

		if err != nil {
			vlogf("Error loading certificates: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		host := client.gateway.Host
		if strings.Contains(host, ":") {
			host, _, err = net.SplitHostPort(host)
			if err != nil {
				vlogf("Unable to Split Host and Port: %s", err)
				resp.Error = err
				resp.Success = false
				return
			}
		}

		conf := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   host,
		}

		transport := http2.Transport{}
		transport.TLSClientConfig = conf

		path := fmt.Sprintf("/3/device/%s", pn.DeviceToken)

		uri, err := client.gateway.Parse(path)
		if err != nil {
			vlogf("Error Parsing Path: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		payload, err := pn.PayloadJSON()
		if err != nil {
			vlogf("Error Converting Payload to JSON: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		buff := bytes.NewBuffer(payload)

		vlogf("Attempting to being APN API Call %s\n", path)

		request, err := http.NewRequest("POST", uri.String(), buff)
		if err != nil {
			vlogf("Error creating an HTTP request: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		request.Header.Add("apns-id", pn.UUID)
		request.Header.Add("apns-priority", fmt.Sprintf("%d", pn.Priority))
		request.Header.Add("apns-expiration", fmt.Sprintf("%d", pn.Expiry))

		vlogf("apns-id: %s", pn.UUID)

		response, err := transport.RoundTrip(request)
		if err != nil {
			vlogf("Error with the request: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		switch statusCode(response.StatusCode) {
		case CodeSuccess:
			vlogf("Push sent successfully\n")
			resp.Success = true
			resp.Error = nil
			return
		default:
		}

		dec := json.NewDecoder(response.Body)

		result := new(APIResponse)
		err = dec.Decode(result)
		if err != nil {
			vlogf("Error decoding the response: %s\n", err)
			resp.Error = err
			resp.Success = false
			return
		}

		switch result.Reason {
		case ReasonPayloadEmpty,
			ReasonPayloadTooLarge,
			ReasonBadTopic,
			ReasonTopicDisallowed,
			ReasonMissingDeviceToken,
			ReasonBadDeviceToken,
			ReasonDeviceTokenNotForTopic,
			ReasonUnregistered,
			ReasonBadCertificateEnvironment,
			ReasonBadCertificate,
			ReasonForbidden,
			ReasonBadPath,
			ReasonMethodNotAllowed,
			ReasonTooManyRequests,
			ReasonMissingTopic:
			fallthrough
		case ReasonBadMessageID,
			ReasonBadExpirationDate,
			ReasonBadPriority:
			fallthrough
		case ReasonDuplicateHeaders:
			vlogf("Push errored: %s\n", result.Reason)
			resp.Error = result.Reason
			resp.Success = false
			return
		default:
			continue
		}
	}

	resp.Error = ErrMaxRetriesExceeded
	resp.Success = false
	return
}
