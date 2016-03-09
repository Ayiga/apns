package apns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

// Push commands always start with command value 2.
const pushCommandValue = 2

// MaxPayloadSizeBytes represents the maximum size of a payload, up to 2KB
const MaxPayloadSizeBytes = 2048

// IdentifierUbound represents the upper bound, or an error identifier.
//
// Every push notification gets a pseudo-unique identifier;
// this establishes the upper boundary for it. Apple will return
// this identifier if there is an issue sending your notification.
const IdentifierUbound = 9999

// Constants related to the payload fields and their lengths.
const (
	deviceTokenItemid            uint8  = 1
	payloadItemid                uint8  = 2
	notificationIdentifierItemid uint8  = 3
	expirationDateItemid         uint8  = 4
	priorityItemid               uint8  = 5
	deviceTokenLength            uint16 = 32
	notificationIdentifierLength uint16 = 4
	expirationDateLength         uint16 = 4
	priorityLength               uint16 = 1
)

func uuuidFormat(s string) string {
	if len(s) == 36 {
		return s
	}

	if len(s) == 32 {
		first := s[:8]
		second := s[8:12]
		third := s[12:16]
		fourth := s[16:20]
		last := s[20:]
		return fmt.Sprintf("%s-%s-%s-%s-%s", first, second, third, fourth, last)
	}

	return s
}

func generateUUID() string {
	id := make([]byte, 16)

	r := 0
	for r < len(id) {
		n, err := rand.Read(id[r:])
		if err != nil {
			return ""
		}
		r += n
	}

	return uuuidFormat(hex.EncodeToString(id))
}

// Payload contains the notification data for your request.
//
// Alert is an interface here because it supports either a string
// or a dictionary, represented within by an AlertDictionary struct.
type Payload struct {
	Alert            interface{} `json:"alert,omitempty"`
	Badge            int         `json:"badge,omitempty"`
	Sound            string      `json:"sound,omitempty"`
	ContentAvailable int         `json:"content-available,omitempty"`
	Category         string      `json:"category,omitempty"`
}

// NewPayload creates and returns a Payload structure.
func NewPayload() *Payload {
	return new(Payload)
}

// AlertDictionary is a more complex notification payload.
//
// From the APN docs: "Use the ... alert dictionary in general only if you absolutely need to."
// The AlertDictionary is suitable for specific localization needs.
type AlertDictionary struct {
	Title        string   `json:"title,omitempty"`
	Body         string   `json:"body,omitempty"`
	TitleLocKey  string   `json:"title-loc-key,omitempty"`
	TitleLocArgs []string `json:"title-loc-args,omitempty"`
	ActionLocKey string   `json:"action-loc-key,omitempty"`
	LocKey       string   `json:"loc-key,omitempty"`
	LocArgs      []string `json:"loc-args,omitempty"`
	LaunchImage  string   `json:"launch-image,omitempty"`
}

// NewAlertDictionary creates and returns an AlertDictionary structure.
func NewAlertDictionary() *AlertDictionary {
	return new(AlertDictionary)
}

// PushNotification is the wrapper for the Payload.
// The length fields are computed in ToBytes() and aren't represented here.
type PushNotification struct {
	UUID        string
	Identifier  int32
	Expiry      uint32
	DeviceToken string
	payload     map[string]interface{}
	Priority    uint8
}

// NewPushNotification creates and returns a PushNotification structure.
// It also initializes the pseudo-random identifier.
func NewPushNotification() (pn *PushNotification) {
	return &PushNotification{
		UUID:       generateUUID(),
		payload:    map[string]interface{}{},
		Identifier: rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(IdentifierUbound),
		Priority:   10,
	}
}

// AddPayload sets the "aps" payload section of the request. It also
// has a hack described within to deal with specific zero values.
func (pn *PushNotification) AddPayload(p *Payload) {
	// This deserves some explanation.
	//
	// Setting an exported field of type int to 0
	// triggers the omitempty behavior if you've set it.
	// Since the badge is optional, we should omit it if
	// it's not set. However, we want to include it if the
	// value is 0, so there's a hack in push_notification.go
	// that exploits the fact that Apple treats -1 for a
	// badge value as though it were 0 (i.e. it clears the
	// badge but doesn't stop the notification from going
	// through successfully.)
	//
	// Still a hack though :)
	if p.Badge == 0 {
		p.Badge = -1
	}
	pn.Set("aps", p)
}

// Get returns the value of a payload key, if it exists.
func (pn *PushNotification) Get(key string) interface{} {
	return pn.payload[key]
}

// Set defines the value of a payload key.
func (pn *PushNotification) Set(key string, value interface{}) {
	pn.payload[key] = value
}

// PayloadJSON returns the current payload in JSON format.
func (pn *PushNotification) PayloadJSON() ([]byte, error) {
	return json.Marshal(pn.payload)
}

// PayloadString returns the current payload in string format.
func (pn *PushNotification) PayloadString() (string, error) {
	j, err := pn.PayloadJSON()
	return string(j), err
}

// ToBytes returns a byte array of the complete PushNotification
// struct. This array is what should be transmitted to the APN Service.
func (pn *PushNotification) ToBytes() ([]byte, error) {
	token, err := hex.DecodeString(pn.DeviceToken)
	if err != nil {
		return nil, err
	}
	if uint16(len(token)) != deviceTokenLength {
		return nil, errors.New("device token has incorrect length")
	}
	payload, err := pn.PayloadJSON()
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPayloadSizeBytes {
		return nil, errors.New("payload is larger than the " + strconv.Itoa(MaxPayloadSizeBytes) + " byte limit")
	}

	frameBuffer := new(bytes.Buffer)
	binary.Write(frameBuffer, binary.BigEndian, deviceTokenItemid)
	binary.Write(frameBuffer, binary.BigEndian, deviceTokenLength)
	binary.Write(frameBuffer, binary.BigEndian, token)
	binary.Write(frameBuffer, binary.BigEndian, payloadItemid)
	binary.Write(frameBuffer, binary.BigEndian, uint16(len(payload)))
	binary.Write(frameBuffer, binary.BigEndian, payload)
	binary.Write(frameBuffer, binary.BigEndian, notificationIdentifierItemid)
	binary.Write(frameBuffer, binary.BigEndian, notificationIdentifierLength)
	binary.Write(frameBuffer, binary.BigEndian, pn.Identifier)
	binary.Write(frameBuffer, binary.BigEndian, expirationDateItemid)
	binary.Write(frameBuffer, binary.BigEndian, expirationDateLength)
	binary.Write(frameBuffer, binary.BigEndian, pn.Expiry)
	binary.Write(frameBuffer, binary.BigEndian, priorityItemid)
	binary.Write(frameBuffer, binary.BigEndian, priorityLength)
	binary.Write(frameBuffer, binary.BigEndian, pn.Priority)

	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, uint8(pushCommandValue))
	binary.Write(buffer, binary.BigEndian, uint32(frameBuffer.Len()))
	binary.Write(buffer, binary.BigEndian, frameBuffer.Bytes())
	return buffer.Bytes(), nil
}
