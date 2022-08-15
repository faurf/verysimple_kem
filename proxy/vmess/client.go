package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	mr "math/rand"

	"io"
	"net"
	"net/url"
	"runtime"
	"strings"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/e1732a364fed/v2ray_simple/netLayer"
	"github.com/e1732a364fed/v2ray_simple/proxy"
	"github.com/e1732a364fed/v2ray_simple/utils"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const systemAutoWillUseAes = runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64"

func init() {
	proxy.RegisterClient(Name, ClientCreator{})
}

type ClientCreator struct{}

func (ClientCreator) NewClientFromURL(url *url.URL) (proxy.Client, error) {
	return nil, errors.New("public key too long to be put into url")
}

func (ClientCreator) NewClient(dc *proxy.DialConf) (proxy.Client, error) {
	uuid, err := utils.StrToUUID(dc.Uuid)
	if err != nil {
		return nil, err
	}
	c := &Client{}
	c.V2rayUser = utils.V2rayUser(uuid)
	c.opt = OptChunkStream

	hasSetSecurityByExtra := false

	if len(dc.Extra) > 0 {
		if thing := dc.Extra["vmess_security"]; thing != nil {
			if str, ok := thing.(string); ok {

				err = c.specifySecurityByStr(str)

				if err == nil {
					hasSetSecurityByExtra = true
				} else {
					return nil, err
				}

			}
		}
		if thing := dc.Extra["server_publickey"]; thing != nil {
			if str, ok := thing.(string); ok {
				ds, err := hex.DecodeString(str)
				if err != nil {
					return nil, err
				}
				c.srvpub.Unpack(ds)
			}
		}
	}

	if !hasSetSecurityByExtra {
		c.specifySecurityByStr("")
	}

	return c, nil
}

type Client struct {
	proxy.Base
	utils.V2rayUser

	srvpub   kyber512.PublicKey
	opt      byte
	security byte
}

func (c *Client) specifySecurityByStr(security string) error {
	security = strings.ToLower(security)
	switch security {
	case "aes-256-gcm":
		c.security = SecurityAES256GCM
	case "chacha20-poly1305":
		c.security = SecurityChacha20Poly1305
	case "auto":
		if systemAutoWillUseAes {
			c.security = SecurityAES256GCM
		} else {
			c.security = SecurityChacha20Poly1305

		}
	case "none":
		c.security = SecurityNone

	case "", "zero": // NOTE: use basic format when no method specified.

		c.opt = OptBasicFormat
		c.security = SecurityNone
	default:
		return utils.ErrInErr{ErrDesc: "unknown security type", ErrDetail: utils.ErrInvalidData, Data: security}
	}
	return nil
}

func (c *Client) Name() string { return Name }

func (c *Client) Handshake(underlay net.Conn, firstPayload []byte, target netLayer.Addr) (io.ReadWriteCloser, error) {
	return c.commonHandshake(underlay, firstPayload, target)
}

func (c *Client) EstablishUDPChannel(underlay net.Conn, firstPayload []byte, target netLayer.Addr) (netLayer.MsgConn, error) {
	return c.commonHandshake(underlay, firstPayload, target)

}

func (c *Client) commonHandshake(underlay net.Conn, firstPayload []byte, target netLayer.Addr) (*ClientConn, error) {

	conn := &ClientConn{
		V2rayUser: c.V2rayUser,
		Conn:      underlay,
		opt:       c.opt,
		port:      uint16(target.Port),
		pub:       c.srvpub,
		security:  c.security,
	}

	conn.addr, conn.atyp = target.AddressBytes()

	var err error

	// Request
	if target.IsUDP() {
		err = conn.handshake(CmdUDP, firstPayload)
		conn.theTarget = target

	} else {
		err = conn.handshake(CmdTCP, firstPayload)

	}

	if err != nil {
		return nil, err
	}

	return conn, err
}

// ClientConn is a connection to vmess server
type ClientConn struct {
	net.Conn

	utils.V2rayUser
	opt      byte
	security byte

	theTarget netLayer.Addr

	atyp byte
	addr []byte
	port uint16

	pub kyber512.PublicKey

	sharedsecret [kyber512.SharedKeySize]byte
	dataReader   io.Reader
	dataWriter   io.Writer

	vmessout []byte
}

func (c *ClientConn) CloseConnWithRaddr(_ netLayer.Addr) error {
	return c.Conn.Close()
}

//return false; vmess 标准 是不支持 fullcone的，和vless v0相同
func (c *ClientConn) Fullcone() bool {
	return false
}

func (c *ClientConn) ReadMsgFrom() (bs []byte, target netLayer.Addr, err error) {
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

func (c *ClientConn) WriteMsgTo(b []byte, _ netLayer.Addr) error {
	_, e := c.Write(b)
	return e
}

// handshake sends request to server.
// data:=[Encap 768][AuthID 16][opt 1][sceurity 1][paddinglen 1][cmd 1][port 1BE][atyp 1][addr 1/4/16][padding 0-16]
// smalldata:=[opt 1][sceurity 1][paddinglen 1][cmd 1][port 1BE][atyp 1][addr 1/4/16][padding 0-16]
// Seal1(len(smalldata)) Seal2(smalldata)

func (c *ClientConn) handshake(cmd byte, firstpayload []byte) error {
	buf := utils.GetBuf()
	defer utils.PutBuf(buf)

	//Encapsulataion
	ciphertext := utils.GetBytes(kyber512.CiphertextSize)
	defer utils.PutBytes(ciphertext)
	c.pub.EncapsulateTo(ciphertext, c.sharedsecret[:], nil)
	buf.Write(ciphertext)

	authid := utils.GetBytes(authid_len)
	defer utils.PutBytes(authid)
	kdf(sha3.NewShake256(), c.V2rayUser[:], authid, ciphertext, []byte(kdfSaltConstAEADAuthID), c.V2rayUser[:])

	buf.Write(authid)
	buf.WriteByte(c.opt)
	buf.WriteByte(c.security)
	// pLen
	paddingLen := mr.Intn(16)
	buf.WriteByte(byte(paddingLen))
	buf.WriteByte(cmd)

	// target
	err := binary.Write(buf, binary.BigEndian, c.port)
	if err != nil {
		return err
	}

	buf.WriteByte(c.atyp)
	buf.Write(c.addr)

	// padding
	if paddingLen > 0 {
		padding := utils.GetBytes(paddingLen)
		defer utils.PutBytes(padding)
		n, err := rand.Read(padding)
		if err != nil {
			return err
		} else if n != paddingLen {
			return errors.New("failed to pad")
		}
		buf.Write(padding)
	}

	c.vmessout = sealAEADHeader(c.sharedsecret[:], buf.Bytes())

	_, err = c.Write(firstpayload)

	return err

}

func (c *ClientConn) Write(b []byte) (n int, err error) {
	if c.dataWriter != nil {
		return c.dataWriter.Write(b)
	}
	c.dataWriter = c.Conn

	switchChan := make(chan struct{})
	var outBuf *bytes.Buffer
	if len(b) == 0 {
		_, err = c.Conn.Write(c.vmessout)
		c.vmessout = nil
		if err != nil {
			return 0, err
		}
	} else {
		outBuf = bytes.NewBuffer(c.vmessout)
		writer := &utils.WriteSwitcher{
			Old:        outBuf,
			New:        c.Conn,
			SwitchChan: switchChan,
			Closer:     c.Conn,
		}

		c.dataWriter = writer
	}

	if c.opt&OptChunkStream > 0 {
		//Client to server derived key:
		//cts:h(commonsecret|kdfSaltConstAEADKey|"Client"|uuid)
		cts := utils.GetBytes(chacha20poly1305.KeySize)
		defer utils.PutBytes(cts)
		nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
		defer utils.PutBytes(nonce)

		h := sha3.NewShake256()
		kdf(h, c.sharedsecret[:], cts, []byte(kdfSaltConstAEADKey), []byte("Client"), c.V2rayUser[:])

		switch c.security {
		case SecurityNone:
			c.dataWriter = ChunkedWriter(c.dataWriter)

		case SecurityAES256GCM:
			block, _ := aes.NewCipher(cts)
			aead, _ := cipher.NewGCM(block)
			kdf(h, c.sharedsecret[:], nonce[:aead.NonceSize()], []byte(kdfSaltConstAEADIV), []byte("Client"), c.V2rayUser[:])
			c.dataWriter = AEADWriter(c.dataWriter, aead, nonce[:aead.NonceSize()], nil)

		case SecurityChacha20Poly1305:
			kdf(h, c.sharedsecret[:], nonce, []byte(kdfSaltConstAEADIV), []byte("Client"), c.V2rayUser[:])
			aead, _ := chacha20poly1305.NewX(cts)
			c.dataWriter = AEADWriter(c.dataWriter, aead, nonce, nil)
		}
	}

	if len(b) > 0 {
		n, err = c.dataWriter.Write(b)
		close(switchChan)
		c.vmessout = nil
		if err != nil {
			return n, err
		}
		_, err = c.Conn.Write(outBuf.Bytes())
	}

	return n, err
}

func (c *ClientConn) Read(b []byte) (n int, err error) {
	if c.dataReader != nil {
		return c.dataReader.Read(b)
	}

	c.dataReader = c.Conn
	if c.opt&OptChunkStream > 0 {
		stc := utils.GetBytes(chacha20poly1305.KeySize)
		nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
		defer utils.PutBytes(stc)
		defer utils.PutBytes(nonce)

		h := sha3.NewShake256()
		kdf(h, c.sharedsecret[:], stc, []byte(kdfSaltConstAEADKey), []byte("Server"), c.V2rayUser[:])

		switch c.security {
		case SecurityNone:
			c.dataReader = ChunkedReader(c.Conn)

		case SecurityAES256GCM:
			block, _ := aes.NewCipher(stc)
			aead, _ := cipher.NewGCM(block)
			kdf(h, c.sharedsecret[:], nonce[:aead.NonceSize()], []byte(kdfSaltConstAEADIV), []byte("Server"), c.V2rayUser[:])
			c.dataReader = AEADReader(c.Conn, aead, nonce[:aead.NonceSize()], nil)

		case SecurityChacha20Poly1305:
			aead, _ := chacha20poly1305.NewX(stc)
			kdf(h, c.sharedsecret[:], nonce, []byte(kdfSaltConstAEADIV), []byte("Server"), c.V2rayUser[:])
			c.dataReader = AEADReader(c.Conn, aead, nonce, nil)
		}
	}

	return c.dataReader.Read(b)
}
