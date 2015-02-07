// This file was generated by counterfeiter
package fakes

import (
	"io"
	"sync"

	"github.com/concourse/atc"
	"github.com/concourse/atc/exec"
)

type FakeExecuteDelegate struct {
	InitializingStub        func(atc.BuildConfig)
	initializingMutex       sync.RWMutex
	initializingArgsForCall []struct {
		arg1 atc.BuildConfig
	}
	StartedStub        func()
	startedMutex       sync.RWMutex
	startedArgsForCall []struct{}
	FinishedStub        func(exec.ExitStatus)
	finishedMutex       sync.RWMutex
	finishedArgsForCall []struct {
		arg1 exec.ExitStatus
	}
	FailedStub        func(error)
	failedMutex       sync.RWMutex
	failedArgsForCall []struct {
		arg1 error
	}
	StdoutStub        func() io.Writer
	stdoutMutex       sync.RWMutex
	stdoutArgsForCall []struct{}
	stdoutReturns struct {
		result1 io.Writer
	}
	StderrStub        func() io.Writer
	stderrMutex       sync.RWMutex
	stderrArgsForCall []struct{}
	stderrReturns struct {
		result1 io.Writer
	}
}

func (fake *FakeExecuteDelegate) Initializing(arg1 atc.BuildConfig) {
	fake.initializingMutex.Lock()
	fake.initializingArgsForCall = append(fake.initializingArgsForCall, struct {
		arg1 atc.BuildConfig
	}{arg1})
	fake.initializingMutex.Unlock()
	if fake.InitializingStub != nil {
		fake.InitializingStub(arg1)
	}
}

func (fake *FakeExecuteDelegate) InitializingCallCount() int {
	fake.initializingMutex.RLock()
	defer fake.initializingMutex.RUnlock()
	return len(fake.initializingArgsForCall)
}

func (fake *FakeExecuteDelegate) InitializingArgsForCall(i int) atc.BuildConfig {
	fake.initializingMutex.RLock()
	defer fake.initializingMutex.RUnlock()
	return fake.initializingArgsForCall[i].arg1
}

func (fake *FakeExecuteDelegate) Started() {
	fake.startedMutex.Lock()
	fake.startedArgsForCall = append(fake.startedArgsForCall, struct{}{})
	fake.startedMutex.Unlock()
	if fake.StartedStub != nil {
		fake.StartedStub()
	}
}

func (fake *FakeExecuteDelegate) StartedCallCount() int {
	fake.startedMutex.RLock()
	defer fake.startedMutex.RUnlock()
	return len(fake.startedArgsForCall)
}

func (fake *FakeExecuteDelegate) Finished(arg1 exec.ExitStatus) {
	fake.finishedMutex.Lock()
	fake.finishedArgsForCall = append(fake.finishedArgsForCall, struct {
		arg1 exec.ExitStatus
	}{arg1})
	fake.finishedMutex.Unlock()
	if fake.FinishedStub != nil {
		fake.FinishedStub(arg1)
	}
}

func (fake *FakeExecuteDelegate) FinishedCallCount() int {
	fake.finishedMutex.RLock()
	defer fake.finishedMutex.RUnlock()
	return len(fake.finishedArgsForCall)
}

func (fake *FakeExecuteDelegate) FinishedArgsForCall(i int) exec.ExitStatus {
	fake.finishedMutex.RLock()
	defer fake.finishedMutex.RUnlock()
	return fake.finishedArgsForCall[i].arg1
}

func (fake *FakeExecuteDelegate) Failed(arg1 error) {
	fake.failedMutex.Lock()
	fake.failedArgsForCall = append(fake.failedArgsForCall, struct {
		arg1 error
	}{arg1})
	fake.failedMutex.Unlock()
	if fake.FailedStub != nil {
		fake.FailedStub(arg1)
	}
}

func (fake *FakeExecuteDelegate) FailedCallCount() int {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return len(fake.failedArgsForCall)
}

func (fake *FakeExecuteDelegate) FailedArgsForCall(i int) error {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return fake.failedArgsForCall[i].arg1
}

func (fake *FakeExecuteDelegate) Stdout() io.Writer {
	fake.stdoutMutex.Lock()
	fake.stdoutArgsForCall = append(fake.stdoutArgsForCall, struct{}{})
	fake.stdoutMutex.Unlock()
	if fake.StdoutStub != nil {
		return fake.StdoutStub()
	} else {
		return fake.stdoutReturns.result1
	}
}

func (fake *FakeExecuteDelegate) StdoutCallCount() int {
	fake.stdoutMutex.RLock()
	defer fake.stdoutMutex.RUnlock()
	return len(fake.stdoutArgsForCall)
}

func (fake *FakeExecuteDelegate) StdoutReturns(result1 io.Writer) {
	fake.StdoutStub = nil
	fake.stdoutReturns = struct {
		result1 io.Writer
	}{result1}
}

func (fake *FakeExecuteDelegate) Stderr() io.Writer {
	fake.stderrMutex.Lock()
	fake.stderrArgsForCall = append(fake.stderrArgsForCall, struct{}{})
	fake.stderrMutex.Unlock()
	if fake.StderrStub != nil {
		return fake.StderrStub()
	} else {
		return fake.stderrReturns.result1
	}
}

func (fake *FakeExecuteDelegate) StderrCallCount() int {
	fake.stderrMutex.RLock()
	defer fake.stderrMutex.RUnlock()
	return len(fake.stderrArgsForCall)
}

func (fake *FakeExecuteDelegate) StderrReturns(result1 io.Writer) {
	fake.StderrStub = nil
	fake.stderrReturns = struct {
		result1 io.Writer
	}{result1}
}

var _ exec.ExecuteDelegate = new(FakeExecuteDelegate)