// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package service

// TraceService provides traces related services.
type TraceService interface {
	// ListIDs lists trace ids
	ListIDs() ([]string, error)
	List() (*Trace, error)
	// ListSBOMs lists SBOMs from a trace
	ListSBOMs(traceID string) ([]string, error)
}

type Trace struct {
	Data []TraceData `json:"data"`
}

type TraceData struct {
	TraceID   string         `json:"traceID"`
	Spans     []TraceSpan    `json:"spans"`
	Processes TraceProcesses `json:"processes"`
}

type TraceSpan struct {
	TraceID       string               `json:"traceID"`
	SpanID        string               `json:"spanID"`
	OperationName string               `json:"operationName"`
	References    []TraceSpanReference `json:"references"`
	StartTime     int64                `json:"startTime"`
	Duration      int                  `json:"duration"`
	Tags          []TraceTag           `json:"tags"`
	ProcessID     string               `json:"processID"`
}

type TraceProcesses struct {
	P1 TraceProcess `json:"p1"`
}

type TraceProcess struct {
	ServiceName string     `json:"serviceName"`
	Tags        []TraceTag `json:"tags"`
}

type TraceTag struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type TraceSpanReference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}
