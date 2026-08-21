package winrm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CalypsoSys/bobwinrm/soap"
	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
)

// Encryption is the NTLM message-encryption transport. The WinRM MIME codec
// is protocol neutral; Kerberos uses the same codec from ClientKerberos.
type Encryption struct {
	ntlm              *ClientNTLM
	protocol          string
	protocolString    []byte
	httpClient        *http.Client
	ntlmClient        *ntlmssp.Client
	ntlmhttp          *ntlmhttp.Client
	messageEncryption *winRMMessageEncryption
}

// NewEncryption creates an NTLM WinRM message-encryption transport.
// Kerberos message encryption is configured on ClientKerberos because that
// transport owns the Kerberos realm, SPN, credentials, and security context.
func NewEncryption(protocol string) (*Encryption, error) {
	if protocol != "ntlm" {
		return nil, fmt.Errorf("encryption for protocol %q not supported by this constructor", protocol)
	}
	return &Encryption{
		ntlm:           &ClientNTLM{},
		protocol:       protocol,
		protocolString: []byte("application/HTTP-SPNEGO-session-encrypted"),
	}, nil
}

func (e *Encryption) Transport(endpoint *Endpoint) error {
	if err := e.ntlm.Transport(endpoint); err != nil {
		return err
	}
	e.httpClient = &http.Client{Transport: e.ntlm.transport}
	return nil
}

func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	if e.httpClient == nil {
		return "", fmt.Errorf("NTLM encryption transport is not initialized")
	}

	userName, domain := splitNTLMUser(client.username)
	var err error
	e.ntlmClient, err = ntlmssp.NewClient(
		ntlmssp.SetUserInfo(userName, client.password),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return "", fmt.Errorf("create NTLM client: %w", err)
	}
	e.ntlmhttp, err = ntlmhttp.NewClient(e.httpClient, e.ntlmClient)
	if err != nil {
		return "", fmt.Errorf("create NTLM HTTP client: %w", err)
	}

	if err := e.PrepareRequest(client, client.url); err != nil {
		// Preserve the existing behavior: if message encryption negotiation is
		// unavailable, make the request through the regular NTLM transport.
		return e.ntlm.Post(client, message)
	}

	e.messageEncryption, err = newWinRMMessageEncryption("ntlm", ntlmMessageProtector{client: e.ntlmClient})
	if err != nil {
		return "", err
	}
	return e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
}

func splitNTLMUser(user string) (name, domain string) {
	if before, after, found := strings.Cut(user, "@"); found {
		return before, after
	}
	if before, after, found := strings.Cut(user, "\\"); found {
		return after, before
	}
	return user, ""
}

func (e *Encryption) PrepareRequest(_ *Client, endpoint string) error {
	if e.ntlmhttp == nil {
		return fmt.Errorf("NTLM HTTP client is not initialized")
	}
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}
	setWinRMHeaders(req, "application/soap+xml;charset=UTF-8", 0)

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return fmt.Errorf("negotiate NTLM message encryption: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read NTLM negotiation response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NTLM negotiation returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (e *Encryption) PrepareEncryptedRequest(_ *Client, endpoint string, message []byte) (string, error) {
	if e.messageEncryption == nil || e.ntlmhttp == nil {
		return "", fmt.Errorf("NTLM message encryption is not initialized")
	}
	encryptedMessage, err := e.messageEncryption.encrypt(message)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(encryptedMessage))
	if err != nil {
		return "", err
	}
	setWinRMHeaders(req, e.messageEncryption.contentType(), len(encryptedMessage))

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return "", fmt.Errorf("send encrypted NTLM request: %w", err)
	}
	body, err := e.ParseEncryptedResponse(resp)
	return string(body), err
}

func setWinRMHeaders(req *http.Request, contentType string, contentLength int) {
	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(contentLength)
}

func (e *Encryption) ParseEncryptedResponse(response *http.Response) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("NTLM response is nil")
	}
	if e.messageEncryption != nil && strings.Contains(response.Header.Get("Content-Type"), fmt.Sprintf(`protocol="%s"`, e.messageEncryption.protocolString)) {
		return e.messageEncryption.decryptResponse(response)
	}
	if response.Body == nil {
		return nil, fmt.Errorf("NTLM response body is nil")
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

// Compatibility helpers retained for tests and callers in this package.
func (e *Encryption) decryptResponse(response *http.Response, _ string) ([]byte, error) {
	if e.messageEncryption == nil {
		return nil, fmt.Errorf("NTLM message encryption is not initialized")
	}
	return e.messageEncryption.decryptResponse(response)
}

func (e *Encryption) decryptMessage(encryptedData []byte, _ string) ([]byte, error) {
	return e.decryptNtlmMessage(encryptedData, "")
}

func (e *Encryption) decryptNtlmMessage(encryptedData []byte, _ string) ([]byte, error) {
	return (ntlmMessageProtector{client: e.ntlmClient}).Unwrap(encryptedData)
}

func (e *Encryption) buildMessage(message []byte, _ string) ([]byte, error) {
	return e.buildNTLMMessage(message, "")
}

func (e *Encryption) buildNTLMMessage(message []byte, _ string) ([]byte, error) {
	return (ntlmMessageProtector{client: e.ntlmClient}).Wrap(message)
}

type ntlmMessageProtector struct {
	client *ntlmssp.Client
}

func (p ntlmMessageProtector) Wrap(message []byte) ([]byte, error) {
	if p.client == nil || p.client.SecuritySession() == nil {
		return nil, fmt.Errorf("NTLM security session is not established")
	}
	sealed, signature, err := p.client.SecuritySession().Wrap(message)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, 4+len(signature)+len(sealed)))
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(signature))); err != nil {
		return nil, err
	}
	buf.Write(signature)
	buf.Write(sealed)
	return buf.Bytes(), nil
}

func (p ntlmMessageProtector) Unwrap(encryptedData []byte) ([]byte, error) {
	if p.client == nil || p.client.SecuritySession() == nil {
		return nil, fmt.Errorf("NTLM security session is not established")
	}
	if len(encryptedData) < 4 {
		return nil, fmt.Errorf("NTLM encrypted payload is shorter than its length prefix")
	}
	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	if signatureLength < 0 || signatureLength > len(encryptedData)-4 {
		return nil, fmt.Errorf("invalid NTLM signature length %d for payload of %d bytes", signatureLength, len(encryptedData))
	}
	signature := encryptedData[4 : 4+signatureLength]
	sealed := encryptedData[4+signatureLength:]
	return p.client.SecuritySession().Unwrap(sealed, signature)
}
