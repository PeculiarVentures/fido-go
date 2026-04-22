package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

var specs = map[string]string{
	"https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html": "docs/raw/fido/ctap/2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html",
	"https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html": "docs/raw/fido/ctap/2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html",
	"https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html": "docs/raw/fido/ctap/2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html",
	"https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html": "docs/raw/fido/ctap/2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html",
	"https://fidoalliance.org/specs/common-specs/fido-glossary-v2.1-ps-20220523.html":                                  "docs/raw/fido/common-specs/fido-glossary-v2.1-ps-20220523.html",
	"https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html":                                  "docs/raw/fido/common-specs/fido-registry-v2.2-ps-20220523.html",
	"https://fidoalliance.org/specs/common-specs/fido-security-ref-v2.1-ps-20220523.html":                              "docs/raw/fido/common-specs/fido-security-ref-v2.1-ps-20220523.html",
	"https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html":                                   "docs/raw/fido/mds/fido-metadata-service-v3.1-ps-20250521.html",
	"https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1-ps-20250521.html":                                 "docs/raw/fido/mds/fido-metadata-statement-v3.1-ps-20250521.html",
	"https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html":      "docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html",
	"https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html":                 "docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html",
	"https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html":             "docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html",
}

func main() {
	for url, dest := range specs {
		if err := downloadSpec(url, dest); err != nil {
			fmt.Fprintf(os.Stderr, "failed to download %q: %v\n", url, err)
			os.Exit(1)
		}
	}
	fmt.Println("FIDO raw specs downloaded successfully.")
}

func downloadSpec(url, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("skipping existing file: %s\n", dest)
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://fidoalliance.org/specs/")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	fmt.Printf("downloaded %s -> %s\n", url, dest)
	return nil
}
