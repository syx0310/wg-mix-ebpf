package faketcp

// Linux perf rings may append up to seven unspecified bytes. Trim only when
// the FakeTCP header proves one exact compact/fixed sample length; malformed
// records remain unmodified and are rejected by DecodeEventSample.
func canonicalPerfEventSample(sample []byte) []byte {
	length := len(sample)
	if length < fakeTCPEventSize {
		return append([]byte(nil), sample...)
	}
	event := decodeEventHeader(sample[:fakeTCPEventSize])
	expected := fakeTCPEventSize
	if fakeTCPEventCarriesPacket(event.Type) {
		packetLength := int(event.PacketLength)
		if packetLength <= 0 || packetLength > fakeTCPPacketEventSize-fakeTCPEventSize {
			return append([]byte(nil), sample...)
		}
		expected += packetLength
		if length >= fakeTCPPacketEventSize && length-fakeTCPPacketEventSize <= 7 {
			expected = fakeTCPPacketEventSize
		}
	}
	if length < expected || length-expected > 7 {
		return append([]byte(nil), sample...)
	}
	return append([]byte(nil), sample[:expected]...)
}
