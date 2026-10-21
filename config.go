package quic

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// Clone clones a Config.
func (c *Config) Clone() *Config {
	copy := *c
	return &copy
}

func (c *Config) handshakeTimeout() time.Duration {
	return 2 * c.HandshakeIdleTimeout
}

func (c *Config) maxRetryTokenAge() time.Duration {
	return c.handshakeTimeout()
}

func validateConfig(config *Config) error {
	if config == nil {
		return nil
	}
	if config.InitialRTT < 0 {
		return fmt.Errorf("invalid initial RTT: %s", config.InitialRTT)
	}
	if config.InitialCongestionWindowPackets != 0 && (config.InitialCongestionWindowPackets < 2 || config.InitialCongestionWindowPackets > protocol.MaxCongestionWindowPackets) {
		return fmt.Errorf("invalid initial congestion window: %d packets", config.InitialCongestionWindowPackets)
	}
	if config.MaxCryptoStreamSize != 0 && (config.MaxCryptoStreamSize < 4096 || config.MaxCryptoStreamSize > quicvarint.Max) {
		return fmt.Errorf("invalid maximum CRYPTO stream size: %d", config.MaxCryptoStreamSize)
	}
	const maxStreams = 1 << 60
	if config.MaxIncomingStreams > maxStreams {
		config.MaxIncomingStreams = maxStreams
	}
	if config.MaxIncomingUniStreams > maxStreams {
		config.MaxIncomingUniStreams = maxStreams
	}
	if config.MaxStreamReceiveWindow > quicvarint.Max {
		config.MaxStreamReceiveWindow = quicvarint.Max
	}
	if config.MaxConnectionReceiveWindow > quicvarint.Max {
		config.MaxConnectionReceiveWindow = quicvarint.Max
	}
	if config.MaxPacketSize != 0 {
		if config.MaxPacketSize < protocol.MinInitialPacketSize || config.MaxPacketSize > protocol.MaxPacketBufferSize {
			return fmt.Errorf("invalid maximum packet size: %d (must be between %d and %d)", config.MaxPacketSize, protocol.MinInitialPacketSize, protocol.MaxPacketBufferSize)
		}
		if config.InitialPacketSize > config.MaxPacketSize {
			return fmt.Errorf("initial packet size %d exceeds maximum packet size %d", config.InitialPacketSize, config.MaxPacketSize)
		}
	}
	if config.InitialPacketSize > 0 && config.InitialPacketSize < protocol.MinInitialPacketSize {
		config.InitialPacketSize = protocol.MinInitialPacketSize
	}
	if config.InitialPacketSize > protocol.MaxPacketBufferSize {
		config.InitialPacketSize = protocol.MaxPacketBufferSize
	}
	// check that all QUIC versions are actually supported
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return fmt.Errorf("invalid QUIC version: %s", v)
		}
	}
	return nil
}

// populateConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	initialCongestionWindowPackets := config.InitialCongestionWindowPackets
	if initialCongestionWindowPackets == 0 {
		initialCongestionWindowPackets = protocol.DefaultInitialCongestionWindowPackets
	}
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}
	maxCryptoStreamSize := config.MaxCryptoStreamSize
	if maxCryptoStreamSize == 0 {
		maxCryptoStreamSize = protocol.MaxCryptoStreamOffset
	}
	handshakeIdleTimeout := protocol.DefaultHandshakeIdleTimeout
	if config.HandshakeIdleTimeout != 0 {
		handshakeIdleTimeout = config.HandshakeIdleTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.MaxIdleTimeout != 0 {
		idleTimeout = config.MaxIdleTimeout
	}
	initialStreamReceiveWindow := config.InitialStreamReceiveWindow
	if initialStreamReceiveWindow == 0 {
		initialStreamReceiveWindow = protocol.DefaultInitialMaxStreamData
	}
	maxStreamReceiveWindow := config.MaxStreamReceiveWindow
	if maxStreamReceiveWindow == 0 {
		maxStreamReceiveWindow = protocol.DefaultMaxReceiveStreamFlowControlWindow
	}
	initialConnectionReceiveWindow := config.InitialConnectionReceiveWindow
	if initialConnectionReceiveWindow == 0 {
		initialConnectionReceiveWindow = protocol.DefaultInitialMaxData
	}
	maxConnectionReceiveWindow := config.MaxConnectionReceiveWindow
	if maxConnectionReceiveWindow == 0 {
		maxConnectionReceiveWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindow
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}
	maxPacketSize := config.MaxPacketSize
	if maxPacketSize == 0 {
		maxPacketSize = protocol.MaxPacketBufferSize
	}
	initialPacketSize := config.InitialPacketSize
	if initialPacketSize == 0 {
		initialPacketSize = min(uint16(protocol.InitialPacketSize), maxPacketSize)
	}

	return &Config{
		InitialCongestionWindowPackets:   initialCongestionWindowPackets,
		GetConfigForClient:               config.GetConfigForClient,
		Versions:                         versions,
		InitialRTT:                       config.InitialRTT,
		MaxCryptoStreamSize:              maxCryptoStreamSize,
		HandshakeIdleTimeout:             handshakeIdleTimeout,
		MaxIdleTimeout:                   idleTimeout,
		KeepAlivePeriod:                  config.KeepAlivePeriod,
		InitialStreamReceiveWindow:       initialStreamReceiveWindow,
		MaxStreamReceiveWindow:           maxStreamReceiveWindow,
		InitialConnectionReceiveWindow:   initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:       maxConnectionReceiveWindow,
		AllowConnectionWindowIncrease:    config.AllowConnectionWindowIncrease,
		MaxIncomingStreams:               maxIncomingStreams,
		MaxIncomingUniStreams:            maxIncomingUniStreams,
		TokenStore:                       config.TokenStore,
		EnableDatagrams:                  config.EnableDatagrams,
		InitialPacketSize:                initialPacketSize,
		MaxPacketSize:                    maxPacketSize,
		DisablePathMTUDiscovery:          config.DisablePathMTUDiscovery,
		EnableStreamResetPartialDelivery: config.EnableStreamResetPartialDelivery,
		Allow0RTT:                        config.Allow0RTT,
		Tracer:                           config.Tracer,
	}
}
