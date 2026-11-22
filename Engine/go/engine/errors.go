// SPDX-License-Identifier: MIT

package engine

import (
	"errors"
	"fmt"
)

// Code mirrors wgex_error_t (02-architecture §6.2).
type Code int32

// Error codes returned through the C ABI.
const (
	OK            Code = 0
	EINVAL        Code = -1
	ENOMEM        Code = -2
	EHANDLE       Code = -3
	ETUN          Code = -4
	EBIND         Code = -5
	ECONFIG       Code = -6
	EUP           Code = -7
	ESTATE        Code = -8
	EDEVICECLOSED Code = -9
	EINTERNAL     Code = -99
)

// Error carries a Code and the underlying cause. Messages never contain UAPI
// values.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return fmt.Sprintf("wgex error %d: %v", e.Code, e.Err) }

func (e *Error) Unwrap() error { return e.Err }

func errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

func wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Code: code, Err: err}
}

// CodeOf maps an error to its Code: OK for nil, EINTERNAL for errors that do
// not carry one.
func CodeOf(err error) Code {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return EINTERNAL
}

// ABIVersion changes whenever the public engine ABI layout or error contract changes.
const ABIVersion int32 = 2
