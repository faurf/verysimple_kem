package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"

	"io"
	"net"
	"net/url"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/e1732a364fed/v2ray_simple/netLayer"
	"github.com/e1732a364fed/v2ray_simple/proxy"
	"github.com/e1732a364fed/v2ray_simple/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

func init() {
	proxy.RegisterServer(Name, &ServerCreator{})
}

func authUserByAuthList(encap, recAuthID []byte, authList []utils.V2rayUser) (user utils.V2rayUser, err error) {
	for _, u := range authList {
		failreason := tryMatchAuthID(encap, recAuthID, u[:])
		switch failreason {
		case 0:
			err = utils.ErrInvalidData
		case 1:
			return u, nil
		}
	}
	if err == nil {
		err = utils.ErrNoMatch

	}
	return
}

type ServerCreator struct{}

func (ServerCreator) NewServerFromURL(url *url.URL) (proxy.Server, error) {

	return nil, errors.New("public key too long to be put into url")
}

func (ServerCreator) NewServer(lc *proxy.ListenConf) (proxy.Server, error) {
	uuidStr := lc.Uuid

	s := NewServer()

	if uuidStr != "" {
		vmessUser, err := utils.NewV2rayUser(uuidStr)
		if err != nil {
			return nil, err
		}
		s.addUser(vmessUser)
	}

	if len(lc.Users) > 0 {
		us := utils.InitRealV2rayUsers(lc.Users)
		for _, u := range us {
			s.addUser(u)
		}
	}
	if len(lc.Extra) > 0 {
		if thing := lc.Extra["server_privatekey"]; thing != nil {
			if str, ok := thing.(string); ok {
				ds, err := hex.DecodeString(str)
				if err != nil {
					return nil, err
				}
				s.srvpri.Unpack(ds)
			}
		}
	}
	return s, nil

}

type Server struct {
	proxy.Base

	*utils.MultiUserMap

	authList []utils.V2rayUser
	srvpri   kyber512.PrivateKey
}

func NewServer() *Server {
	s := &Server{
		MultiUserMap: utils.NewMultiUserMap(),
	}
	s.SetUseUUIDStr_asKey()
	return s
}
func (s *Server) Name() string { return Name }

func (s *Server) addUser(u utils.V2rayUser) {
	s.MultiUserMap.AddUser_nolock(u)
	s.authList = append(s.authList, u)
}

type ksession struct {
	uid          utils.V2rayUser
	mastersecret [kyber512.SharedKeySize]byte
}

func (s *Server) Handshake(underlay net.Conn) (tcpConn net.Conn, msgConn netLayer.MsgConn, targetAddr netLayer.Addr, returnErr error) {
	if err := proxy.SetCommonReadTimeout(underlay); err != nil {
		returnErr = err
		return
	}
	defer netLayer.PersistConn(underlay)

	data := utils.GetPacket()
	defer utils.PutPacket(data)

	n, err := underlay.Read(data)
	if err != nil {
		returnErr = err
		return
	} else if n < kyber512.CiphertextSize {
		returnErr = utils.NumErr{E: errors.New("too little data"), N: 1}
		return
	}

	var ks ksession

	ks.uid, err = authUserByAuthList(data[:kyber512.CiphertextSize], data[kyber512.CiphertextSize:kyber512.CiphertextSize+authid_len], s.authList)
	if err != nil {
		returnErr = err
		return
	}
	s.srvpri.DecapsulateTo(ks.mastersecret[:], data[:kyber512.CiphertextSize])

	remainBuf := bytes.NewBuffer(data[kyber512.CiphertextSize+authid_len : n])

	aeadData, bytesRead, errorReason := openAEADHeader(ks.mastersecret[:], remainBuf)
	if errorReason != nil {
		returnErr = errorReason

		if ce := utils.CanLogWarn("vmess openAEADHeader err"); ce != nil {

			ce.Write(zap.Any("things", []any{errorReason, bytesRead}))
		}

		return
	}
	if len(aeadData) < 8 {
		returnErr = utils.NumErr{E: utils.ErrInvalidData, N: 3}
		return
	}

	//https://www.v2fly.org/developer/protocols/vmess.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
	sc := &ServerConn{
		Conn:      underlay,
		V2rayUser: ks.uid,
		opt:       aeadData[0],
		security:  aeadData[1],
		cmd:       aeadData[3],
	}
	copy(sc.sharedsecret[:], ks.mastersecret[:])

	paddingLen := int(aeadData[2])
	aeadDataBuf := bytes.NewBuffer(aeadData[4:])

	switch sc.cmd {

	case CmdTCP, CmdUDP:
		ad, err := netLayer.V2rayGetAddrFrom(aeadDataBuf)
		if err != nil {
			returnErr = utils.NumErr{E: utils.ErrInvalidData, N: 4}
			return
		}
		sc.theTarget = ad
		if sc.cmd == CmdUDP {
			ad.Network = "udp"
		}
		targetAddr = ad
	}
	if paddingLen > 0 {
		tmpBs := aeadDataBuf.Next(paddingLen)
		if len(tmpBs) != paddingLen {
			returnErr = utils.NumErr{E: utils.ErrInvalidData, N: 5}
			return
		}
	}

	sc.remainReadBuf = remainBuf

	buf := utils.GetBuf()
	defer utils.PutBuf(buf)
	sc.firstWriteBuf = buf

	if sc.cmd == CmdTCP {
		tcpConn = sc

	} else {
		msgConn = sc
	}

	return
}

type ServerConn struct {
	net.Conn

	utils.V2rayUser
	opt      byte
	security byte
	cmd      byte

	theTarget netLayer.Addr

	remainReadBuf, firstWriteBuf *bytes.Buffer

	dataReader   io.Reader
	dataWriter   io.Writer
	sharedsecret [kyber512.SharedKeySize]byte
}

func (c *ServerConn) Write(b []byte) (n int, err error) {

	if c.dataWriter != nil {
		return c.dataWriter.Write(b)
	}
	switchChan := make(chan struct{})

	//使用 WriteSwitcher 来 粘连 服务器vmess响应 以及第一个数据响应
	writer := &utils.WriteSwitcher{
		Old:        c.firstWriteBuf,
		New:        c.Conn,
		SwitchChan: switchChan,
		Closer:     c.Conn,
	}

	c.dataWriter = writer

	stc := utils.GetBytes(chacha20poly1305.KeySize)
	nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
	defer utils.PutBytes(stc)
	defer utils.PutBytes(nonce)

	h := sha3.NewShake256()
	kdf(h, c.sharedsecret[:], stc, []byte(kdfSaltConstAEADKey), []byte("Server"), c.V2rayUser[:])

	if c.opt&OptChunkStream == OptChunkStream {

		switch c.security {
		case SecurityNone:
			c.dataWriter = ChunkedWriter(writer)
		case SecurityAES256GCM:
			block, _ := aes.NewCipher(stc)
			aead, _ := cipher.NewGCM(block)
			kdf(h, c.sharedsecret[:], nonce[:aead.NonceSize()], []byte(kdfSaltConstAEADIV), []byte("Server"), c.V2rayUser[:])
			c.dataWriter = AEADWriter(writer, aead, nonce[:aead.NonceSize()], nil)

		case SecurityChacha20Poly1305:
			aead, _ := chacha20poly1305.NewX(stc)
			kdf(h, c.sharedsecret[:], nonce, []byte(kdfSaltConstAEADIV), []byte("Server"), c.V2rayUser[:])
			c.dataWriter = AEADWriter(writer, aead, nonce, nil)
		}
	}

	n, err = c.dataWriter.Write(b)

	close(switchChan)
	if err != nil {
		return n, err
	}
	_, err = c.Conn.Write(c.firstWriteBuf.Bytes())
	utils.PutBuf(c.firstWriteBuf)
	c.firstWriteBuf = nil
	return n, err

}

func (c *ServerConn) Read(b []byte) (n int, err error) {
	if c.dataReader != nil {
		return c.dataReader.Read(b)
	}
	var curReader io.Reader
	if c.remainReadBuf != nil && c.remainReadBuf.Len() > 0 {
		curReader = io.MultiReader(c.remainReadBuf, c.Conn)
	} else {
		curReader = c.Conn
	}

	cts := utils.GetBytes(chacha20poly1305.KeySize)
	nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
	defer utils.PutBytes(cts)
	defer utils.PutBytes(nonce)

	h := sha3.NewShake256()
	kdf(h, c.sharedsecret[:], cts, []byte(kdfSaltConstAEADKey), []byte("Client"), c.V2rayUser[:])

	if c.opt&OptChunkStream > 0 {
		switch c.security {
		case SecurityNone:
			c.dataReader = ChunkedReader(curReader)

		case SecurityAES256GCM:
			block, _ := aes.NewCipher(cts)
			aead, _ := cipher.NewGCM(block)
			kdf(h, c.sharedsecret[:], nonce[:aead.NonceSize()], []byte(kdfSaltConstAEADIV), []byte("Client"), c.V2rayUser[:])
			c.dataReader = AEADReader(curReader, aead, nonce[:aead.NonceSize()], nil)

		case SecurityChacha20Poly1305:
			aead, _ := chacha20poly1305.NewX(cts)
			kdf(h, c.sharedsecret[:], nonce, []byte(kdfSaltConstAEADIV), []byte("Client"), c.V2rayUser[:])
			c.dataReader = AEADReader(curReader, aead, nonce, nil)
		}

	}

	return c.dataReader.Read(b)

}

func (c *ServerConn) ReadMsgFrom() (bs []byte, target netLayer.Addr, err error) {
	bs = utils.GetPacket()
	var n int
	n, err = c.Read(bs)
	if err != nil {
		utils.PutPacket(bs)
		bs = nil
		return
	}
	bs = bs[:n]
	target = c.theTarget
	return
}

func (c *ServerConn) WriteMsgTo(b []byte, _ netLayer.Addr) error {
	_, e := c.Write(b)
	return e
}
func (c *ServerConn) CloseConnWithRaddr(_ netLayer.Addr) error {
	return c.Conn.Close()
}
func (c *ServerConn) Fullcone() bool {
	return false
}
