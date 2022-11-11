package output

import (
	"context"
	"fmt"

	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type contextKey string

func (c contextKey) String() string {
	return "output context key " + string(c)
}

var (
	contextKeyProgressBar = contextKey("progress-bar")
)

type Progress struct {
	progress *mpb.Progress
}

func NewProgress() *Progress {
	return &Progress{
		progress: mpb.New(),
	}
}

func (p *Progress) BeforeHook() recon.BeforeHookFunc {
	return func(ctx context.Context, service string, regions []string) context.Context {
		name := fmt.Sprintf("enumerate %s", service)

		bar := p.progress.AddBar(int64(len(regions)),
			mpb.PrependDecorators(
				decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DidentRight}),
				decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "done"),
			),
			mpb.AppendDecorators(decor.Percentage()),
		)

		return context.WithValue(ctx, contextKeyProgressBar, bar)
	}
}

func (p *Progress) AfterRunHook() recon.AfterRunHookFunc {
	return func(ctx context.Context, service, region string) context.Context {
		if bar, ok := ctx.Value(contextKeyProgressBar).(*mpb.Bar); ok {
			bar.Increment()
		}

		return ctx
	}
}

func (p *Progress) Wait() {
	p.progress.Wait()
}
