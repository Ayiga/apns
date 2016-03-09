package apns

import (
	"crypto/tls"
	"errors"
	"golang.org/x/net/context"
	"net"
	"net/url"
	"strings"
	// "sync"
	"time"
)

// the binary provider api tends to be of the following format, url wise:
//
// gateway.push.apple.com:2195
// gateway.sandbox.push.apple.com:2195

func getURL(rawurl string) (u *url.URL, err error) {
	if !strings.HasPrefix(rawurl, "https://") {
		rawurl = "https://" + rawurl
	}

	u, err = url.Parse(rawurl)
	return
}

// GatewayClient contains the fields necessary to communicate
// with Apple, such as the gateway to use and your
// certificate contents.
//
// You'll need to provide your own certificateFile
// and keyFile to send notifications. Ideally, you'll
// just set the certificateFile and keyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the certificateBase64
// and keyBase64 fields to store the actual contents.
type GatewayClient struct {
	gateway           *url.URL
	certificateFile   string
	certificateBase64 string
	keyFile           string
	keyBase64         string

	idleConn  chan *tls.Conn
	connCount int

	maxIdle     int
	maxOpen     int
	maxLifetime time.Duration
}

const (
	defaultMaxIdle = 10
	defaultMaxOpen = 20
)

// BareGatewayClient can be used to set the contents of your
// certificate and key blocks manually.
func BareGatewayClient(gateway, certificateBase64, keyBase64 string) (c Client) {
	uri, err := getURL(gateway)
	if err != nil {
		return nil
	}

	client := &GatewayClient{
		gateway:           uri,
		certificateBase64: certificateBase64,
		keyBase64:         keyBase64,
		maxIdle:           defaultMaxIdle,
		maxOpen:           defaultMaxOpen,
		idleConn:          make(chan *tls.Conn, defaultMaxIdle),
	}

	return client
}

// NewGatewayClient assumes you'll be passing in paths that
// point to your certificate and key.
func NewGatewayClient(gateway, certificateFile, keyFile string) (c Client) {
	uri, err := getURL(gateway)
	if err != nil {
		return nil
	}

	client := &GatewayClient{
		gateway:         uri,
		certificateFile: certificateFile,
		keyFile:         keyFile,
		maxIdle:         defaultMaxIdle,
		maxOpen:         defaultMaxOpen,
		idleConn:        make(chan *tls.Conn, defaultMaxIdle),
	}

	return client
}

// SetMaxConns will set the maximum number of connections usable within the
// connection pool
func (client *GatewayClient) SetMaxConns(m int) {
	client.maxOpen = m

}

// SetMaxIdleConns will set the maximum number of Idle Connections to remain
// open at a given time
func (client *GatewayClient) SetMaxIdleConns(m int) {
	client.maxIdle = m

	previousIdleConns := client.idleConn
	client.idleConn = make(chan *tls.Conn, m)
	i := 0
	for c := range previousIdleConns {
		if i < m {
			client.idleConn <- c
			i++
		} else {
			// close this idle connection
			client.connCount--
			c.Close()
		}
	}
	close(previousIdleConns)
}

const (
	getConnAttemptCount int = 2
)

// gets a connection from the pool, or opens a new one
func (client *GatewayClient) getConn() (*tls.Conn, error) {
	vlogf("attempting to get a connection")
	var i = 0
	for i < getConnAttemptCount {
		select {
		case c := <-client.idleConn:
			vlogf("Found an idle connection")
			return c, nil
		default:
			if client.connCount < client.maxOpen {
				c, err := client.dial()
				if err != nil {
					// we had an issue opening a connection
					i++
					vlogf("Unable to dial: %s", err)
					continue
				}

				return c, nil
			}
		}
		time.Sleep(time.Millisecond)
	}

	err := errors.New("Unable to retrieve a connection")
	vlogf("error: %s", err)
	return nil, err
}

// put's the connection back in the pool
func (client *GatewayClient) putConn(c *tls.Conn) {
	client.idleConn <- c
}

// dial will attempt to establish a new tls.Conn
func (client *GatewayClient) dial() (*tls.Conn, error) {
	vlogf("Attempting to Open a new connection")
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
		vlogf("Error loading certs: %s", err)
		return nil, err
	}

	var host, port string
	if strings.Contains(client.gateway.Host, ":") {
		host, port, err = net.SplitHostPort(client.gateway.Host)
		if err != nil {
			vlogf("Erro splitting Host and port: %s\n", err)
			return nil, err
		}
	}
	if port == "" {
		port = "2195"
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   host,
	}

	conn, err := tls.Dial("tcp", host+":"+port, conf)
	if err != nil {
		vlogf("Error opening connection: %s", err)
		conn.Close()
		return nil, err
	}

	client.connCount++
	return conn, nil
}

// Send connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (client *GatewayClient) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)
	conn, err := client.getConn()
	if err != nil {
		vlogf("Error retrieving a connection: %s", err)
		return &PushNotificationResponse{
			Error:   err,
			Success: false,
		}
	}

	bytes, err := pn.ToBytes()
	if err != nil {
		vlogf("Error converting payload: %s", err)
		resp.Success = false
		resp.Error = err
		return
	}
	w := 0
	for w < len(bytes) {
		i, err := conn.Write(bytes[w:])
		if err != nil {
			vlogf("Error writing to connection: %s", err)
			return &PushNotificationResponse{
				Error:   err,
				Success: false,
			}
		}
		w += i
		time.Sleep(time.Millisecond)
	}

	defer client.putConn(conn)

	responseChannel := make(chan []byte, 1)
	defer close(responseChannel)
	go func() {
		b := make([]byte, 6)
		r := 0
		for r < len(b) {
			i, err := conn.Read(b[r:])
			if err != nil {
				vlogf("Unable to Read from Connection: %s\n", err)
				return // well... crap... must have some big error.
			}
			r += i
		}

		responseChannel <- b
	}()

	ctx, _ := context.WithTimeout(context.Background(), TimeoutSeconds*time.Second)

	select {
	case b := <-responseChannel:
		vlogf("Apple Binary API Error: %s", AppleResponseCode(b[1]))
		resp.AppleResponse = AppleResponseCode(b[1])
		resp.Error = AppleResponseCode(b[1])
		resp.Success = false
	case <-ctx.Done():
		// deadline exceeded...
	}
	return
}
