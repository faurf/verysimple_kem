/*Package vmess implements vmess client.*/
package vmess

const Name = "vmess"

// Request Options
const (
	OptBasicFormat  byte = 0 // 基本格式
	OptChunkStream  byte = 1 // 标准格式,实际的请求数据被分割为若干个小块
	OptChunkMasking byte = 2
)

// Security types
const (
	SecurityAES256GCM        byte = 1
	SecurityChacha20Poly1305 byte = 2
	SecurityNone             byte = 3
)

//vmess CMD types
const (
	CmdTCP byte = 1
	CmdUDP byte = 2
)
