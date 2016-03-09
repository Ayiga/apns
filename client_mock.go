package apns

import "github.com/stretchr/testify/mock"

// MockClient implements Client
type MockClient struct {
	mock.Mock
}

// Send implements Client
func (m *MockClient) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	r := m.Called(pn).Get(0)
	if r != nil {
		if r, ok := r.(*PushNotificationResponse); ok {
			return r
		}
	}
	return nil
}

// SetMaxConns implements Client
func (*MockClient) SetMaxConns(m int) {}

// SetMaxIdleConns implements Client
func (*MockClient) SetMaxIdleConns(m int) {}
