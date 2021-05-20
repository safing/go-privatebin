package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/safing/go-privatebin/privatebin"
	"github.com/safing/go-privatebin/types"
)

const (
	pbDefaultURL        = "vim.cx"
	pbDefaultExpiration = "1week"
)

var version string = "DEV"
var date string

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	versionPtr := flag.BoolP("version", "v", false, "display version")
	urlPtr := flag.StringP("url", "u", pbDefaultURL, "privatebin host")
	attachmentPtr := flag.StringP("attach", "a", "", "attach a file")
	expiration := types.ExpirationValue("1week")
	flag.VarP(&expiration, "expire", "e", "expiration")
	flag.Parse()

	if *versionPtr {
		fmt.Println("Version: " + version + " (built on " + date + ")")
		return
	}

	pbURL := strings.TrimRight(*urlPtr, "/")
	if !strings.Contains(pbURL, "://") {
		pbURL = "https://" + pbURL
	}

	// Read from STDIN (Piped input)
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read from stdin: %s", err)
	}

	// Remove extra line breaks to prevent PrivateBin from breaking.
	if bytes.HasSuffix(input, []byte("\n")) {
		input = input[:len(input)-1]
	}

	// create a new privatebin client
	client, err := privatebin.NewClient(pbURL, nil)
	if err != nil {
		log.Fatalf("failed to create client: %s", err)
	}

	// prepare the attachment, if any
	var (
		r        io.Reader
		fileName string
		ctx      = context.Background()
	)
	if *attachmentPtr != "" {
		f, err := os.Open(*attachmentPtr)
		if err != nil {
			log.Fatalf("failed to open attachment at %s: %s", *attachmentPtr, err)
		}
		fileName = filepath.Base(*attachmentPtr)
		r = f
	}

	accessURL, err := client.PasteWithAttachment(
		ctx,
		expiration,
		string(input),
		fileName,
		r,
	)
	if err != nil {
		log.Fatalf("failed to create paste: %s", err)
	}

	fmt.Println(accessURL)
}
