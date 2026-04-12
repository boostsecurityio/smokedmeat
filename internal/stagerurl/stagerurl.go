// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package stagerurl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	routeSegment = "smokedmeat"
	idPrefix     = "stg_sm_"
)

func Path(id string) string {
	return "/r/" + routeSegment + "/" + id
}

func Join(baseURL, id string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/") + Path(id)
}

func URL(baseURL, id string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	u.Path = path.Join("/", u.Path, "r", routeSegment, id)
	return u.String(), nil
}

func IDFromPath(p string) (string, bool) {
	id := strings.TrimPrefix(p, "/r/"+routeSegment+"/")
	return id, id != "" && id != p
}

func GenerateID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s%x", idPrefix, time.Now().UnixNano())
	}
	return idPrefix + hex.EncodeToString(buf[:])
}
