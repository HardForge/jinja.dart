package eciesgo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPublicKeyFromHex(t *testing.T) {
	_, err := NewPublicKeyFromHex(testingReceiverPubkeyHex)
	assert.NoError(t