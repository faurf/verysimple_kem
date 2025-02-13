package tlsLayer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/e1732a364fed/v2ray_simple/netLayer"
	"github.com/e1732a364fed/v2ray_simple/utils"
	"go.uber.org/zap"
)

//https://www.ihcblog.com/a-better-tls-obfs-proxy/
//https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-cn.md

func getShadowTlsPasswordFromExtra(extra map[string]any) string {
	if len(extra) > 0 {
		if thing := extra["shadowtls_password"]; thing != nil {
			if str, ok := thing.(string); ok {
				return str
			}
		}
	}
	return ""
}

func shadowTls1(servername string, clientConn net.Conn) (tlsConn *Conn, err error) {
	var fakeConn net.Conn
	fakeConn, err = net.Dial("tcp", servername+":443")
	if err != nil {
		if ce := utils.CanLogErr("Failed shadowTls server fake dial server "); ce != nil {
			ce.Write(zap.Error(err))
		}
		return
	}
	if ce := utils.CanLogDebug("shadowTls ready to fake "); ce != nil {
		ce.Write()
	}

	var e1, e2 error

	finish1 := make(chan struct{})
	go func() {
		e1 = CopyTls12Handshake(true, fakeConn, clientConn)

		if ce := utils.CanLogDebug("shadowTls copy client end"); ce != nil {
			ce.Write(zap.Error(e1))
		}

		close(finish1)

	}()

	e2 = CopyTls12Handshake(false, clientConn, fakeConn)

	if ce := utils.CanLogDebug("shadowTls copy server end"); ce != nil {
		ce.Write(
			zap.Error(e2),
		)
	}

	<-finish1

	if e1 != nil || e2 != nil {
		e := utils.Errs{List: []utils.ErrsItem{
			{Index: 1, E: e1},
			{Index: 2, E: e2},
		}}

		return nil, e
	}

	if ce := utils.CanLogDebug("shadowTls fake ok "); ce != nil {
		ce.Write()
	}

	tlsConn = &Conn{
		Conn: clientConn,
	}

	return
}

func shadowTls2(servername string, clientConn net.Conn, password string) (tlsConn *Conn, err error) {
	var fakeConn net.Conn
	fakeConn, err = net.Dial("tcp", servername+":443")
	if err != nil {
		if ce := utils.CanLogErr("Failed shadowTls2 server fake dial server "); ce != nil {
			ce.Write(zap.Error(err))
		}
		return
	}
	if ce := utils.CanLogDebug("shadowTls2 ready to fake "); ce != nil {
		ce.Write()
	}

	hashW := utils.NewHashWriter(clientConn, []byte(password))
	go io.Copy(hashW, fakeConn)
	var firstPayload *bytes.Buffer
	firstPayload, err = shadowCopyHandshakeClientToFake(fakeConn, clientConn, hashW)

	if err == nil {
		fakeConn.Close()

		if ce := utils.CanLogDebug("shadowTls2 fake ok!"); ce != nil {
			ce.Write()
		}

		realconn := &FakeAppDataConn{
			Conn: clientConn,
		}

		allDataConn := &netLayer.IOWrapper{
			Reader: &utils.ReadWrapper{
				Reader:            realconn,
				OptionalReader:    firstPayload,
				RemainFirstBufLen: firstPayload.Len(),
			},
			Writer: realconn,
		}

		return &Conn{
			Conn: allDataConn,
		}, nil
	} else if err == utils.ErrFailed {
		if ce := utils.CanLogWarn("shadowTls2 fake failed!"); ce != nil {
			ce.Write()
		}

		hashW.StopHashing()
		go io.Copy(fakeConn, clientConn)
		return nil, errors.New("not real shadowTlsClient, fallback")
	}
	return nil, err

}

func shadowCopyHandshakeClientToFake(fakeConn, clientConn net.Conn, hashW *utils.HashWriter) (*bytes.Buffer, error) {
	var header [5]byte
	step := 0
	var applicationDataCount int

	buf := utils.GetBuf()

	for {
		if ce := utils.CanLogDebug("shadowTls2 copy "); ce != nil {
			ce.Write(zap.Int("step", step))
		}

		netLayer.SetCommonReadTimeout(clientConn)

		_, err := io.ReadFull(clientConn, header[:])

		netLayer.PersistConn(clientConn)

		if err != nil {
			return nil, utils.ErrInErr{ErrDetail: err, ErrDesc: "shadowTls2, io.ReadFull err"}
		}

		contentType := header[0]

		length := binary.BigEndian.Uint16(header[3:])
		if ce := utils.CanLogDebug("shadowTls2 copy "); ce != nil {
			ce.Write(zap.Int("step", step),
				zap.Uint8("contentType", contentType),
				zap.Uint16("length", length),
			)
		}

		if contentType == 23 {

			netLayer.SetCommonReadTimeout(clientConn)

			_, err = io.Copy(buf, io.LimitReader(clientConn, int64(length)))

			netLayer.PersistRead(clientConn)

			if err != nil {
				utils.PutBuf(buf)
				return nil, utils.ErrInErr{ErrDetail: err, ErrDesc: "shadowTls2, copy err1"}
			}

			if hashW.Written() && length >= 8 {

				checksum := hashW.Sum()
				first8 := buf.Bytes()[:8]

				if ce := utils.CanLogDebug("shadowTls2 check "); ce != nil {
					ce.Write(zap.Int("step", step),
						zap.String("checksum", fmt.Sprintf("%v", checksum)),
						zap.String("real8", fmt.Sprintf("%v", first8)),
					)
				}

				if bytes.Equal(first8, checksum) {
					buf.Next(8)
					return buf, nil
				}
			}

			netLayer.SetCommonWriteTimeout(fakeConn)

			_, err = io.Copy(fakeConn, io.MultiReader(bytes.NewReader(header[:]), buf))

			netLayer.PersistWrite(fakeConn)

			if err != nil {
				utils.PutBuf(buf)
				return nil, utils.ErrInErr{ErrDetail: err, ErrDesc: "shadowTls2, copy err2"}
			}

			buf.Reset()

			applicationDataCount++
		} else {

			netLayer.SetCommonReadTimeout(clientConn)
			netLayer.SetCommonWriteTimeout(fakeConn)

			_, err = io.Copy(fakeConn, io.MultiReader(bytes.NewReader(header[:]), io.LimitReader(clientConn, int64(length))))

			netLayer.PersistRead(clientConn)
			netLayer.PersistWrite(fakeConn)

			if err != nil {
				return nil, utils.ErrInErr{ErrDetail: err, ErrDesc: "shadowTls2, copy err3"}
			}
		}

		const maxAppDataCount = 3
		if applicationDataCount > maxAppDataCount {
			return nil, utils.ErrFailed
		}
		step++

		if step > 8 {
			return nil, errors.New("shadowTls2 copy loop > 8, maybe under attack")

		}
	}

}

// 第一次写时写入一个hash，其余直接使用 FakeAppDataConn
type shadowClientConn struct {
	*FakeAppDataConn
	sum []byte
}

func (c *shadowClientConn) Write(p []byte) (n int, err error) {
	if c.sum != nil {
		sum := c.sum
		c.sum = nil
		buf := utils.GetBuf()
		if ce := utils.CanLogDebug("write hash"); ce != nil {
			ce.Write(zap.Any("sum", fmt.Sprintf("%v", sum)))
		}
		buf.Write(sum)
		buf.Write(p)

		_, err = c.FakeAppDataConn.Write(buf.Bytes())
		utils.PutBuf(buf)

		if err == nil {
			n = len(p)
		}
		return
	}
	return c.FakeAppDataConn.Write(p)
}
