package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

func runPrivacyKey(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" && args[0] != "destroy" {
		return errors.New("privacy-key create|destroy --file ABSOLUTE_PATH; stop key readers before destroy")
	}
	fs := flag.NewFlagSet("privacy-key", flag.ContinueOnError)
	fs.SetOutput(out)
	path := fs.String("file", "", "external privacy key file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected privacy-key arguments")
	}
	var err error
	if args[0] == "create" {
		err = eventstore.CreatePrivacyKey(*path)
	} else {
		err = eventstore.DestroyPrivacyKey(*path)
	}
	if err != nil {
		return errors.New("privacy key operation failed; check private path, permissions and reader shutdown")
	}
	return json.NewEncoder(out).Encode(map[string]any{"operation": args[0], "completed": true})
}

func configuredPrivacyKey(inline, path string) ([]byte, error) {
	if path != "" {
		if inline != "" {
			return nil, errors.New("select graph_key_file or graph_key_hex, not both")
		}
		return eventstore.LoadPrivacyKey(path)
	}
	return key32(inline)
}
