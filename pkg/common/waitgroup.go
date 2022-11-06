package common

import "sync"

type WaitGroup interface {
	Add(delta int)
	Done()
	Wait()
}

type semaphoredWaitGroup struct {
	*sync.WaitGroup
	sem chan struct{}
}

func NewSemaphoredWaitGroup(max int) WaitGroup {
	return &semaphoredWaitGroup{
		sem:       make(chan struct{}, max),
		WaitGroup: new(sync.WaitGroup),
	}
}

func (s *semaphoredWaitGroup) Add(delta int) {
	s.WaitGroup.Add(delta)
	s.sem <- struct{}{}
}

func (s *semaphoredWaitGroup) Done() {
	<-s.sem
	s.WaitGroup.Done()
}
