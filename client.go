package apns

// Client is an APNS client.
type Client interface {
	// ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error)

	// Send will initiate a send of the specified Push Notification, and return
	// a response
	Send(pn *PushNotification) (resp *PushNotificationResponse)
}

// UseHTTP2API informs BareClient and NewClient which communication API to use
var UseHTTP2API = true

// BareClient will create a new Client that will use the base64 certificate and
// key to conduct it's transations
func BareClient(gateway, certificateBase64, keyBase64 string) (c Client) {
	if UseHTTP2API {
		return BareHTTP2Client(gateway, certificateBase64, keyBase64)
	}
	return BareGatewayClient(gateway, certificateBase64, keyBase64)
}

// NewClient will create a new Client that will use the certificate and key at
// the specifies for it's transactions
func NewClient(gateway, certificateFile, keyFile string) (c Client) {
	if UseHTTP2API {
		return NewHTTP2Client(gateway, certificateFile, keyFile)
	}
	return NewGatewayClient(gateway, certificateFile, keyFile)
}
