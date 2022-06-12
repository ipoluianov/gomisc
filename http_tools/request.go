package http_tools

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

func Request(httpClient *http.Client, url string, parameters map[string][]byte) (code int, data []byte, err error) {

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range parameters {
		var fw io.Writer
		fw, err = writer.CreateFormField(key)
		if err != nil {
			return
		}
		_, err = fw.Write(value)
		if err != nil {
			return
		}
	}
	err = writer.Close()
	if err != nil {
		return
	}
	var response *http.Response
	response, err = Post(httpClient, url, writer.FormDataContentType(), &body)
	if err != nil {
		return
	}
	code = response.StatusCode
	data, err = ioutil.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return
	}
	_ = response.Body.Close()
	return
}

func Post(httpClient *http.Client, url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return httpClient.Do(req)
}
