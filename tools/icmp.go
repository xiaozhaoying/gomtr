package tools

const (
	DATA_LEN = 4 // icmp大小
)

type ICMP struct {
	Type       uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	Seq        uint16
	Data       [DATA_LEN]byte
}

// 修改checksum
func (icmp *ICMP) CheckSum(data []byte) {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		length -= 2
		index += 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)
	icmp.Checksum = uint16(^sum)
}
