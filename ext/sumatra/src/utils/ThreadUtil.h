/* Copyright 2012 the SumatraPDF project authors (see AUTHORS file).
   License: Simplified BSD (see COPYING.BSD) */

#ifndef ThreadUtil_h
#define ThreadUtil_h

#include "RefCounted.h"

/* A very simple thread class that allows stopping a thread */
class ThreadBase : public RefCounted {
private:
    LONG                threadNo;
    HANDLE              hThread;
    bool                cancelRequested;

    static DWORD WINAPI ThreadProc(void *data);

protected:
    // for debugging
    ScopedMem<char>     threadName;

    virtual ~ThreadBase();

    // note: no need for Interlocked* since this value is
    //       only ever changed from false to true
    bool WasCancelRequested() { return cancelRequested; }

public:
    // name is for debugging purposes, can be NULL.
    ThreadBase(const char *name=NULL);

    // call this to start executing Run() function.
    void Start();

    // request the thread to stop. It's up to Run() function
    // to call WasCancelRequested() and stop processing if it returns true.
    void RequestCancel() { cancelRequested = true; }

    // ask the thread to stop with RequestCancel() and wait for it to end
    // returns true if thread stopped by itself and false if waiting timed out
    bool RequestCancelAndWaitToStop(DWORD waitMs=INFINITE);

    // get a unique number that identifies a thread and unlike an
    // address of the object, will not be reused
    LONG GetNo() const { return threadNo; }

    // over-write this to implement the actual thread functionality
    // note: for longer running threads, make sure to occasionally poll WasCancelRequested
    virtual void Run() = 0;
};

#endif
