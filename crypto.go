// implementation of https://tools.ietf.org/html/rfc2898#section-6.1.2

package pkcs12

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/Azure/go-pkcs12/rc2"
)

const (
	pbeWithSHAAnd3KeyTripleDESCBC = "pbeWithSHAAnd3-KeyTripleDES-CBC"
	pbewithSHAAnd40BitRC2CBC      = "pbewithSHAAnd40BitRC2-CBC"
)

var (
	oidPbeWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPbewithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

var algByOID = map[string]string{
	oidPbeWithSHAAnd3KeyTripleDESCBC.String(): pbeWithSHAAnd3KeyTripleDESCBC,
	oidPbewithSHAAnd40BitRC2CBC.String():      pbewithSHAAnd40BitRC2CBC,
}

var blockcodeByAlg = map[string]func(key []byte) (cipher.Block, error){
	pbeWithSHAAnd3KeyTripleDESCBC: des.NewTripleDESCipher,
	pbewithSHAAnd40BitRC2CBC: func(key []byte) (cipher.Block, error) {
		return rc2.New(key, len(key)*8)
	},
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

const (
	saltSize = 16
	itCount = 100000
)

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, error) {
	algorithmName, supported := algByOID[algorithm.Algorithm.String()]
	if !supported {
		return nil, NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	var params pbeParams
	if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}

	k := deriveKeyByAlg[algorithmName](params.Salt, password, params.Iterations)
	iv := deriveIVByAlg[algorithmName](params.Salt, password, params.Iterations)
	password = nil

	code, err := blockcodeByAlg[algorithmName](k)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(code, iv)
	return cbc, nil
}

func pbDecrypt(info decryptable, password []byte) (decrypted []byte, err error) {
	cbc, err := pbDecrypterFor(info.GetAlgorithm(), password)
	password = nil
	if err != nil {
		return nil, err
	}

	encrypted := info.GetData()

	decrypted = make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)

	if psLen := int(decrypted[len(decrypted)-1]); psLen > 0 && psLen <= cbc.BlockSize() {
		m := decrypted[:len(decrypted)-psLen]
		ps := decrypted[len(decrypted)-psLen:]
		if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
			return nil, ErrDecryption
		}
		decrypted = m
	} else {
		return nil, ErrDecryption
	}

	return
}

type decryptable interface {
	GetAlgorithm() pkix.AlgorithmIdentifier
	GetData() []byte
}

func generateSalt(password []byte) []byte {
    buff := make([]byte, saltSize, saltSize+sha1.Size)
    _, err := io.ReadFull(rand.Reader, buf)

    if err != nil {
            fmt.Printf("Random read failed: %v", err)
            os.Exit(1)
        }

    hash := sha1.New()
    hash.Write(buf)
    hash.Write(passord)
    return hash.Sum(buf)
}

func pbEncrypterFor(algorithm String, password []byte) (cbc cipher.BlockMode, params pbeParams,  err error){
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. Should I implement this?
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2

	var params pbeParams

	params.Salt = generateSalt(password)
	params.Iterations = itCount

	k := deriveKeyByAlg[algorithmName](params.Salt, params.Iterations)
	iv := deriveIVByAlg[algorithmName](params.Salt, params.Iterations)

	code, err := blockcodeByAlg[algorithmName](k)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(code, iv)
	return cbc, params, nil
}

func pbEnrypt(info []byte, algorithm String, password []byte) (encr encryptedContentInfo, err error){
	cbc, params, err := pbEncrypterFor(algorithm, password)
	if err != nil {
		return nil, err
	}

	encrypted = make([]byte, len(info))
	cbc.CryptBlocks(encrypted, info)

	params, err := asn1.Marshal(params)
	if err != nil {
		return nil, err
	}

	algorithm.Parameters.FullBytes = params
	
	encr = new(encryptedContentInfo)
	encr.Algorithm = algorithm
	encr.EncryptedContent = encrypted
	// Content type could be added in the pkcs12, need to see later.
	encr.ContentType = oidEncryptedDataContentType
	return
}
