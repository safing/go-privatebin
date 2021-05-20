package privatebin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/safing/go-privatebin/types"
	"github.com/safing/go-privatebin/utils"
)

// Client is a PrivateBin client that support posting
// to a PrivateBin instance.
type Client struct {
	httpClient *http.Client
	server     string
}

// NewClient returns a new pastbin client for the PrivateBin
// instance running at server. If cli is nil http.DefaultClient
// will be used.
func NewClient(server string, cli *http.Client) (*Client, error) {
	if cli == nil {
		cli = http.DefaultClient
	}
	if _, err := url.Parse(server); err != nil {
		return nil, fmt.Errorf("invalid server address: %s", err)
	}
	return &Client{
		httpClient: cli,
		server:     server,
	}, nil
}

// Paste encryptes content with a new random key and pastes it
// on the PrivateBin. For attachments, use PasteWithAttachment.
// See PasteWithAttachment for additional notes.
func (cli *Client) Paste(ctx context.Context, expiration types.ExpirationValue, content string) (string, error) {
	return cli.PasteWithAttachment(ctx, expiration, content, "", nil)
}

// PasteWithAttachment is like Paste but supports adding a single
// attachment to the paste. If attachment is nil no attachment is
// added. If attachment is set but no attachmentName is given the
// name defaults to "attachment".
// Note that PasteWithAttachment generates a new random master key
// by using crypto/rand. The caller MUST ensure to seed the random
// number generator before using this client!
func (cli *Client) PasteWithAttachment(ctx context.Context, expiration types.ExpirationValue, content, attachmentName string, attachment io.Reader) (string, error) {
	var attachmentBody string

	// prepare the attachment, if any
	if attachment != nil {
		blob, err := ioutil.ReadAll(attachment)
		if err != nil {
			return "", fmt.Errorf("failed to read attachment: %w", err)
		}
		attachmentBody = base64.StdEncoding.EncodeToString(blob)
		if attachmentName == "" {
			attachmentName = "attachment"
		}
	}

	// generate random bytes for the master key
	// hope that the user called rand.Seed() otherwise
	// this will not be secure!
	key, err := utils.GenRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	// prepare the actual paste. This will be encrypted using AES GCM
	// with key.
	pc := PasteContent{
		Paste:          utils.StripANSI(content),
		Attachment:     attachmentBody,
		AttachmentName: attachmentName,
	}
	blob, err := json.Marshal(pc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal paste: %w", err)
	}

	data, err := Encrypt(key, blob)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// prepare the body structure
	createPasteRequest := &PasteRequest{
		V:     2,
		AData: data.GetAData(),
		Meta: PasteRequestMeta{
			Expire: expiration.String(),
		},
		CT: utils.Base64(data.Data),
	}

	// marshal the body into a JSON payload
	bodyPayload, err := json.Marshal(createPasteRequest)
	if err != nil {
		return "", fmt.Errorf("failed to prepare request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cli.server, bytes.NewReader(bodyPayload))
	if err != nil {
		return "", fmt.Errorf("failed to prepare request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "JSONHttpRequest") // https://github.com/PrivateBin/PrivateBin/wiki/API#as-of-version-022

	// perform the actual request and check the response
	resp, err := cli.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code: %s", resp.Status)
	}

	var pasteResponse PasteResponse
	if err := json.NewDecoder(resp.Body).Decode(&pasteResponse); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	// generate the access URL
	return fmt.Sprintf(
		"%s%s#%s",
		strings.TrimRight(cli.server, "/"),
		pasteResponse.URL,
		base58.Encode(key),
	), nil
}
