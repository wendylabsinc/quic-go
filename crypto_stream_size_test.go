package quic

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestConfigCryptoStreamSize(t *testing.T) {
	require.EqualValues(t, 16<<10, populateConfig(nil).MaxCryptoStreamSize)
	for _, size := range []uint64{4096, 16 << 10, 64 << 10, quicvarint.Max} {
		config := &Config{MaxCryptoStreamSize: size}
		require.NoError(t, validateConfig(config))
		require.Equal(t, size, config.Clone().MaxCryptoStreamSize)
		require.Equal(t, size, populateConfig(config).MaxCryptoStreamSize)
	}
	for _, size := range []uint64{1, 4095, quicvarint.Max + 1, ^uint64(0)} {
		require.Error(t, validateConfig(&Config{MaxCryptoStreamSize: size}))
	}
}

func TestConnectionCryptoStreamSize(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, configured := range []uint64{0, 64 << 10} {
			t.Run(fmt.Sprintf("server=%t/size=%d", server, configured), func(t *testing.T) {
				config := &Config{MaxCryptoStreamSize: configured}
				var tc *testConnection
				if server {
					tc = newServerTestConnection(t, nil, config, false)
				} else {
					tc = newClientTestConnection(t, nil, config, false)
				}
				limit := protocol.ByteCount(16 << 10)
				if configured != 0 {
					limit = protocol.ByteCount(configured)
				}
				for _, level := range []protocol.EncryptionLevel{
					protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT,
				} {
					manager := tc.conn.cryptoStreamManager
					// The default rejects a 24 KiB flight; explicitly opting into
					// 64 KiB accepts it on both endpoints at every encryption level.
					data := bytes.Repeat([]byte{0x42}, 24<<10)
					err := manager.HandleCryptoFrame(&wire.CryptoFrame{Data: data}, level)
					if configured == 0 {
						require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded})
						data = data[:limit]
						require.NoError(t, manager.HandleCryptoFrame(&wire.CryptoFrame{Data: data}, level))
					} else {
						require.NoError(t, err)
					}
					require.Equal(t, data, manager.GetCryptoData(level))
					if end := protocol.ByteCount(len(data)); end < limit {
						tail := bytes.Repeat([]byte{0x43}, int(limit-end))
						require.NoError(t, manager.HandleCryptoFrame(&wire.CryptoFrame{Offset: end, Data: tail}, level))
						require.Equal(t, tail, manager.GetCryptoData(level))
					}
					// Consuming data does not reset the cumulative receive limit.
					require.ErrorIs(t, manager.HandleCryptoFrame(&wire.CryptoFrame{
						Offset: limit, Data: []byte{1},
					}, level), &qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded})
				}
			})
		}
	}
}
