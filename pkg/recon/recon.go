package recon

import (
	"context"
	"sync"

	"github.com/hupe1980/awsrecon/pkg/common"
)

var AWSRegions = []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-north-1", "me-south-1", "sa-east-1"}

type BeforeHookFunc = func(ctx context.Context, service string, regions []string) context.Context

type AfterRunHookFunc = func(ctx context.Context, service string, region string) context.Context

type reconOptions struct {
	IgnoreServices []string
	MaxConcurrency int
	BeforeHook     BeforeHookFunc
	AfterRunHook   AfterRunHookFunc
}

type recon[T any] struct {
	resultChan    chan T
	results       []T
	errorChan     chan error
	errors        []error
	enumerateFunc func()
	wg            common.WaitGroup
	rwg           *sync.WaitGroup
	opts          reconOptions
}

func newRecon[T any](enumerateFunc func(), optFns ...func(o *reconOptions)) *recon[T] {
	opts := reconOptions{
		MaxConcurrency: 20,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	return &recon[T]{
		resultChan:    make(chan T),
		errorChan:     make(chan error),
		enumerateFunc: enumerateFunc,
		wg:            common.NewSemaphoredWaitGroup(opts.MaxConcurrency),
		rwg:           new(sync.WaitGroup),
		opts:          opts,
	}
}

func (r *recon[T]) Run() []T {
	r.rwg.Add(1)

	go func() {
		defer r.rwg.Done()

		for c := range r.errorChan {
			r.errors = append(r.errors, c)
		}
	}()

	r.rwg.Add(1)

	go func() {
		defer r.rwg.Done()

		for c := range r.resultChan {
			r.results = append(r.results, c)
		}
	}()

	r.wg.Add(1)

	go func() {
		defer r.wg.Done()

		r.enumerateFunc()
	}()

	r.wait()

	return r.results
}

func (r *recon[T]) Errors() []error {
	r.wait()

	return r.errors
}

func (r *recon[T]) runEnumerateService(service string, fn func()) {
	if common.SliceContains(r.opts.IgnoreServices, service) {
		return
	}

	ctx := context.TODO()

	if r.opts.BeforeHook != nil {
		ctx = r.opts.BeforeHook(ctx, service, []string{"global"})
	}

	r.wg.Add(1)

	go func(ctx context.Context, fn func()) {
		defer r.wg.Done()
		fn()

		if r.opts.AfterRunHook != nil {
			r.opts.AfterRunHook(ctx, service, "global")
		}
	}(ctx, fn)
}

func (r *recon[T]) runEnumerateServicePerRegion(service string, regions []string, fn func(region string)) {
	if common.SliceContains(r.opts.IgnoreServices, service) {
		return
	}

	ctx := context.TODO()

	if r.opts.BeforeHook != nil {
		ctx = r.opts.BeforeHook(ctx, service, regions)
	}

	for _, region := range regions {
		r.wg.Add(1)

		go func(ctx context.Context, region string, fn func(region string)) {
			defer r.wg.Done()

			fn(region)

			if r.opts.AfterRunHook != nil {
				r.opts.AfterRunHook(ctx, service, region)
			}
		}(ctx, region, fn)
	}
}

func (r *recon[T]) addError(e error) {
	r.errorChan <- e
}

func (r *recon[T]) addResult(result T) {
	r.resultChan <- result
}

func (r *recon[T]) wgAdd(delta int) {
	r.wg.Add(delta)
}

func (r *recon[T]) wgDone() {
	r.wg.Done()
}

func (r *recon[T]) wait() {
	r.wg.Wait()

	close(r.resultChan)
	close(r.errorChan)

	r.rwg.Wait()
}
