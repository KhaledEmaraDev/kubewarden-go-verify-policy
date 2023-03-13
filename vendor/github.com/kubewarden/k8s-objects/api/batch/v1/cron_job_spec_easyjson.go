// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package v1

import (
	json "encoding/json"
	_v11 "github.com/kubewarden/k8s-objects/api/core/v1"
	_v1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV1(in *jlexer.Lexer, out *CronJobSpec) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "concurrencyPolicy":
			out.ConcurrencyPolicy = string(in.String())
		case "failedJobsHistoryLimit":
			out.FailedJobsHistoryLimit = int32(in.Int32())
		case "jobTemplate":
			if in.IsNull() {
				in.Skip()
				out.JobTemplate = nil
			} else {
				if out.JobTemplate == nil {
					out.JobTemplate = new(JobTemplateSpec)
				}
				easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV11(in, out.JobTemplate)
			}
		case "schedule":
			if in.IsNull() {
				in.Skip()
				out.Schedule = nil
			} else {
				if out.Schedule == nil {
					out.Schedule = new(string)
				}
				*out.Schedule = string(in.String())
			}
		case "startingDeadlineSeconds":
			out.StartingDeadlineSeconds = int64(in.Int64())
		case "successfulJobsHistoryLimit":
			out.SuccessfulJobsHistoryLimit = int32(in.Int32())
		case "suspend":
			out.Suspend = bool(in.Bool())
		case "timeZone":
			out.TimeZone = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV1(out *jwriter.Writer, in CronJobSpec) {
	out.RawByte('{')
	first := true
	_ = first
	if in.ConcurrencyPolicy != "" {
		const prefix string = ",\"concurrencyPolicy\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.ConcurrencyPolicy))
	}
	if in.FailedJobsHistoryLimit != 0 {
		const prefix string = ",\"failedJobsHistoryLimit\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.FailedJobsHistoryLimit))
	}
	{
		const prefix string = ",\"jobTemplate\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		if in.JobTemplate == nil {
			out.RawString("null")
		} else {
			easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV11(out, *in.JobTemplate)
		}
	}
	{
		const prefix string = ",\"schedule\":"
		out.RawString(prefix)
		if in.Schedule == nil {
			out.RawString("null")
		} else {
			out.String(string(*in.Schedule))
		}
	}
	if in.StartingDeadlineSeconds != 0 {
		const prefix string = ",\"startingDeadlineSeconds\":"
		out.RawString(prefix)
		out.Int64(int64(in.StartingDeadlineSeconds))
	}
	if in.SuccessfulJobsHistoryLimit != 0 {
		const prefix string = ",\"successfulJobsHistoryLimit\":"
		out.RawString(prefix)
		out.Int32(int32(in.SuccessfulJobsHistoryLimit))
	}
	if in.Suspend {
		const prefix string = ",\"suspend\":"
		out.RawString(prefix)
		out.Bool(bool(in.Suspend))
	}
	if in.TimeZone != "" {
		const prefix string = ",\"timeZone\":"
		out.RawString(prefix)
		out.String(string(in.TimeZone))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v CronJobSpec) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v CronJobSpec) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *CronJobSpec) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *CronJobSpec) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV1(l, v)
}
func easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV11(in *jlexer.Lexer, out *JobTemplateSpec) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "metadata":
			if in.IsNull() {
				in.Skip()
				out.Metadata = nil
			} else {
				if out.Metadata == nil {
					out.Metadata = new(_v1.ObjectMeta)
				}
				(*out.Metadata).UnmarshalEasyJSON(in)
			}
		case "spec":
			if in.IsNull() {
				in.Skip()
				out.Spec = nil
			} else {
				if out.Spec == nil {
					out.Spec = new(JobSpec)
				}
				easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV12(in, out.Spec)
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV11(out *jwriter.Writer, in JobTemplateSpec) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Metadata != nil {
		const prefix string = ",\"metadata\":"
		first = false
		out.RawString(prefix[1:])
		(*in.Metadata).MarshalEasyJSON(out)
	}
	if in.Spec != nil {
		const prefix string = ",\"spec\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV12(out, *in.Spec)
	}
	out.RawByte('}')
}
func easyjson88b473b4DecodeGithubComKubewardenK8sObjectsApiBatchV12(in *jlexer.Lexer, out *JobSpec) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "activeDeadlineSeconds":
			out.ActiveDeadlineSeconds = int64(in.Int64())
		case "backoffLimit":
			out.BackoffLimit = int32(in.Int32())
		case "completionMode":
			out.CompletionMode = string(in.String())
		case "completions":
			out.Completions = int32(in.Int32())
		case "manualSelector":
			out.ManualSelector = bool(in.Bool())
		case "parallelism":
			out.Parallelism = int32(in.Int32())
		case "selector":
			if in.IsNull() {
				in.Skip()
				out.Selector = nil
			} else {
				if out.Selector == nil {
					out.Selector = new(_v1.LabelSelector)
				}
				(*out.Selector).UnmarshalEasyJSON(in)
			}
		case "suspend":
			out.Suspend = bool(in.Bool())
		case "template":
			if in.IsNull() {
				in.Skip()
				out.Template = nil
			} else {
				if out.Template == nil {
					out.Template = new(_v11.PodTemplateSpec)
				}
				(*out.Template).UnmarshalEasyJSON(in)
			}
		case "ttlSecondsAfterFinished":
			out.TTLSecondsAfterFinished = int32(in.Int32())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson88b473b4EncodeGithubComKubewardenK8sObjectsApiBatchV12(out *jwriter.Writer, in JobSpec) {
	out.RawByte('{')
	first := true
	_ = first
	if in.ActiveDeadlineSeconds != 0 {
		const prefix string = ",\"activeDeadlineSeconds\":"
		first = false
		out.RawString(prefix[1:])
		out.Int64(int64(in.ActiveDeadlineSeconds))
	}
	if in.BackoffLimit != 0 {
		const prefix string = ",\"backoffLimit\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.BackoffLimit))
	}
	if in.CompletionMode != "" {
		const prefix string = ",\"completionMode\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.CompletionMode))
	}
	if in.Completions != 0 {
		const prefix string = ",\"completions\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.Completions))
	}
	if in.ManualSelector {
		const prefix string = ",\"manualSelector\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.ManualSelector))
	}
	if in.Parallelism != 0 {
		const prefix string = ",\"parallelism\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.Parallelism))
	}
	if in.Selector != nil {
		const prefix string = ",\"selector\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		(*in.Selector).MarshalEasyJSON(out)
	}
	if in.Suspend {
		const prefix string = ",\"suspend\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.Suspend))
	}
	{
		const prefix string = ",\"template\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		if in.Template == nil {
			out.RawString("null")
		} else {
			(*in.Template).MarshalEasyJSON(out)
		}
	}
	if in.TTLSecondsAfterFinished != 0 {
		const prefix string = ",\"ttlSecondsAfterFinished\":"
		out.RawString(prefix)
		out.Int32(int32(in.TTLSecondsAfterFinished))
	}
	out.RawByte('}')
}
