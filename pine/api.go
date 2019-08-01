package pine

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"bytes"
	"encoding/base64"
	"strconv"
)

const baseUri = "http://localhost:8910"

func SignDigestCompact(hash []byte) ([]byte, error) {
	encodedHash := []byte(base64.StdEncoding.EncodeToString(hash))
	url := fmt.Sprintf("%s/v1/node/signer/sign-message", baseUri)
	resp, err := http.Post(url, "text/plain", bytes.NewReader(encodedHash))

	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	encodedSig, _ := strconv.Unquote(string(body))
	decodedSig, err := base64.StdEncoding.DecodeString(encodedSig)

	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v: %s", err, encodedSig)
	}

	return decodedSig, nil
}
