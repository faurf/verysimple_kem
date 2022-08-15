package vmess

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/e1732a364fed/v2ray_simple/utils"
)

const (
	kdfSaltConstAEADKey         = "AEAD kdfSaltConstKey"
	kdfSaltConstAEADIV          = "AEAD kdfSaltConstIV"
	kdfSaltConstAEADLengthNonce = "AEAD kdfSaltConstLengthNonce"
	kdfSaltConstAEADLengthKey   = "AEAD kdfSaltConstLengthKey"
	kdfSaltConstAEADHeaderNonce = "AEAD kdfSaltConstHeaderNonce"
	kdfSaltConstAEADHeaderKey   = "AEAD kdfSaltConstHeaderKey"
	kdfSaltConstAEADAuthID      = "AEAD kdfSaltConstAuthID"
)

const authid_len = 16

//为1表示匹配成功, 若为0，则hmac 校验失败（正常地匹配失败，不意味着被攻击）
func tryMatchAuthID(Encap, ReceivedAuthID, u []byte) (failReason int) {
	h := sha3.NewShake256()
	data := utils.GetBytes(authid_len)
	defer utils.PutBytes(data)
	kdf(h, u, data, Encap, []byte(kdfSaltConstAEADAuthID), u)
	return subtle.ConstantTimeCompare(data, ReceivedAuthID)
}

func kdf(h sha3.ShakeHash, key, result []byte, info ...[]byte) {
	h.Write(key)
	for _, v := range info {
		h.Write([]byte(v))
	}
	// envelop construction
	h.Write(key)
	h.Read(result)
	h.Reset()
}

func sealAEADHeader(mastersecret, data []byte) []byte {
	h := sha3.NewShake256()
	key := utils.GetBytes(chacha20poly1305.KeySize)
	defer utils.PutBytes(key)
	nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
	defer utils.PutBytes(nonce)
	//length:=realHdrLen-Encap
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)-kyber512.CiphertextSize)-authid_len)
	kdf(h, mastersecret, key, []byte(kdfSaltConstAEADLengthKey))
	lenAEAD, _ := chacha20poly1305.NewX(key)

	kdf(h, mastersecret, nonce, []byte(kdfSaltConstAEADLengthNonce))
	lenEnc := lenAEAD.Seal(nil, nonce, length, nil)
	outputBuffer := &bytes.Buffer{}

	kdf(h, mastersecret, key, []byte(kdfSaltConstAEADHeaderKey))
	hdrAEAD, _ := chacha20poly1305.NewX(key)
	kdf(h, mastersecret, nonce, []byte(kdfSaltConstAEADHeaderNonce))
	hdrEnc := hdrAEAD.Seal(nil, nonce, data[kyber512.CiphertextSize+authid_len:], nil)

	outputBuffer.Write(data[:kyber512.CiphertextSize+authid_len])
	outputBuffer.Write(lenEnc)
	outputBuffer.Write(hdrEnc)
	return outputBuffer.Bytes()
}

func openAEADHeader(mastersecret []byte, remainDataReader io.Reader) (aeadData []byte, bytesRead int, errorReason error) {

	encLen := utils.GetBytes(chacha20poly1305.Overhead + 2)
	defer utils.PutBytes(encLen)
	authidCheckValueReadBytesCounts, err := io.ReadFull(remainDataReader, encLen[:])
	bytesRead += authidCheckValueReadBytesCounts
	if err != nil {
		return nil, bytesRead, err
	}

	key := utils.GetBytes(chacha20poly1305.KeySize)
	defer utils.PutBytes(key)
	nonce := utils.GetBytes(chacha20poly1305.NonceSizeX)
	defer utils.PutBytes(nonce)
	h := sha3.NewShake256()
	var decHdrLenRusult []byte
	kdf(h, mastersecret, key, []byte(kdfSaltConstAEADLengthKey))
	lenAEAD, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err.Error())
	}
	kdf(h, mastersecret, nonce, []byte(kdfSaltConstAEADLengthNonce))
	decHdrLen, erropenAEAD := lenAEAD.Open(nil, nonce, encLen[:], nil)

	if erropenAEAD != nil {
		return nil, bytesRead, erropenAEAD
	}
	decHdrLenRusult = decHdrLen

	var length uint16
	if err := binary.Read(bytes.NewReader(decHdrLenRusult), binary.BigEndian, &length); err != nil {
		panic(err)
	}

	var decHdrRusult []byte

	var HdrEncReadedBytesCounts int
	{
		kdf(h, mastersecret, key, []byte(kdfSaltConstAEADHeaderKey))
		kdf(h, mastersecret, nonce, []byte(kdfSaltConstAEADHeaderNonce))

		encHdr := make([]byte, length+chacha20poly1305.Overhead)

		HdrEncReadedBytesCounts, err = io.ReadFull(remainDataReader, encHdr)
		bytesRead += HdrEncReadedBytesCounts
		if err != nil {
			return nil, bytesRead, err
		}

		hdrAEAD, _ := chacha20poly1305.NewX(key)
		decHdr, erropenAEAD := hdrAEAD.Open(nil, nonce, encHdr, nil)
		if erropenAEAD != nil {
			return nil, bytesRead, erropenAEAD
		}

		decHdrRusult = decHdr
	}

	return decHdrRusult, bytesRead, nil
}
