// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package lint

import (
	"errors"
	"regexp"
	"strings"
)

// Quad is the Quad ID of CP §7.1.2.11: "idType/iD/role[,role...]/owner",
// carried as a UTF8String otherName (OIDQuadID) in subjectAltName.
type Quad struct {
	IDType string
	ID     string
	// Roles is the comma-separated role list as encoded.
	Roles string
	// Owner is empty when the Quad ID has only three fields.
	Owner string
}

// ParseQuad splits a Quad ID string. Three fields (no owner) are accepted;
// Check reports a missing owner.
func ParseQuad(s string) (*Quad, error) {
	f := strings.Split(s, "/")
	if len(f) < 3 || len(f) > 4 {
		return nil, errors.New("want idType/iD/roles/owner")
	}
	for _, v := range f {
		if v == "" {
			return nil, errors.New("empty field")
		}
	}
	q := &Quad{IDType: f[0], ID: f[1], Roles: f[2]}
	if len(f) == 4 {
		q.Owner = f[3]
	}
	return q, nil
}

func (q Quad) String() string {
	s := q.IDType + "/" + q.ID + "/" + q.Roles
	if q.Owner != "" {
		s += "/" + q.Owner
	}
	return s
}

var (
	label     = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`
	fqdnRE    = regexp.MustCompile(`^(` + label + `\.)+` + label + `$`)
	agentPart = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// ValidFQDN reports whether s is a lower-case fully qualified domain name
// with at least two labels.
func ValidFQDN(s string) bool { return len(s) <= 253 && fqdnRE.MatchString(s) }

// ValidAgentID reports whether s is an agent identifier: user@fqdn (the
// form of the CP's agentId example) or an FQDN.
func ValidAgentID(s string) bool {
	user, host, ok := strings.Cut(s, "@")
	if !ok {
		return ValidFQDN(s)
	}
	return agentPart.MatchString(user) && ValidFQDN(host)
}
