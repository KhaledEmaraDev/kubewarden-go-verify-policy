package main

import (
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"

	"fmt"
)

// The Settings class is defined inside of the `types.go` file

// No special checks have to be done
func (s *Settings) Valid() (bool, error) {
	if s.Image == "" {
		return false, fmt.Errorf("image cannot be empty")
	}
	if len(s.PubKeys) == 0 {
		return false, fmt.Errorf("pubKeys cannot be of length 0")
	}
	return true, nil
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := easyjson.Unmarshal(validationReq.Settings, &settings)
	return settings, err
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings := Settings{}
	err := easyjson.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}
