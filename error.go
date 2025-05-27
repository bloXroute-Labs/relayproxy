package relayproxy

type ErrorResp struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"-"`
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

func toErrorResp(code int, msg string, fields map[string]any) *ErrorResp {
	return &ErrorResp{
		Code:    code,
		Message: msg,
		Fields:  fields,
	}
}
