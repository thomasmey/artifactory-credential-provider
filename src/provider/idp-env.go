package main

import "os"

type EnvIDTokenProvider struct{}

func (p EnvIDTokenProvider) GetIDToken(audience, format string) (string, error) {
	return os.Getenv("ID_TOKEN"), nil
}
