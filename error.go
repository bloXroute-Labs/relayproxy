package relayproxy

import (
	"go.uber.org/zap"
)

type ErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`

	fields []zap.Field `json:"-"`
}

func (e *ErrorResp) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}
func (e *ErrorResp) ErrorCode() int {
	if e == nil {
		return 0
	}
	return e.Code
}
func toErrorResp(code int, msg string, fields ...zap.Field) *ErrorResp {
	return &ErrorResp{
		Code:    code,
		Message: msg,
		fields:  fields,
	}
}
