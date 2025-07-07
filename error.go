package relayproxy

type ErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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

func toErrorResp(code int, msg string) *ErrorResp {
	return &ErrorResp{
		Code:    code,
		Message: msg,
	}
}
