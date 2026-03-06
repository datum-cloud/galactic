package remote

import (
	"context"
	"log"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type Remote struct {
	URL            string
	ClientID       string
	Username       string
	Password       string
	QoS            byte
	TopicRX        string
	TopicTX        string
	ReceiveHandler func([]byte) error

	client mqtt.Client
}

func (r *Remote) Run(ctx context.Context) error {
	log.Printf("MQTT connecting")

	opts := mqtt.NewClientOptions().
		AddBroker(r.URL)
	if r.ClientID != "" {
		opts.SetClientID(r.ClientID)
	}
	if r.Username != "" {
		opts.SetUsername(r.Username)
	}
	if r.Password != "" {
		opts.SetPassword(r.Password)
	}
	opts.SetCleanSession(r.ClientID == "" || r.QoS == 0)

	opts.OnConnect = func(c mqtt.Client) {
		log.Println("MQTT connected")
		token := c.Subscribe(
			r.TopicRX,
			r.QoS,
			func(_ mqtt.Client, msg mqtt.Message) {
				payload := msg.Payload()
				if err := r.ReceiveHandler(payload); err != nil {
					log.Printf("MQTT ReceiveHandler failed: %v", err)
				}
			},
		)
		if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
			log.Printf("MQTT subscribe error: %v", token.Error())
			return
		}
		log.Printf("MQTT subscribed: %s", r.TopicRX)
	}

	r.client = mqtt.NewClient(opts)
	if tok := r.client.Connect(); tok.Wait() && tok.Error() != nil {
		return tok.Error()
	}

	<-ctx.Done()
	if r.client.IsConnected() {
		r.client.Disconnect(250)
	}
	log.Println("MQTT disconnected")

	return nil
}

func (r *Remote) Send(payload interface{}) {
	token := r.client.Publish(r.TopicTX, r.QoS, false, payload)
	token.Wait()
}
