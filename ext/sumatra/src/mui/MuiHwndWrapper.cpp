/* Copyright 2012 the SumatraPDF project authors (see AUTHORS file).
   License: Simplified BSD (see COPYING.BSD) */

#include "Mui.h"
#include "WinUtil.h"

#include "DebugLog.h"

namespace mui {

HwndWrapper::HwndWrapper(HWND hwnd)
    : painter(NULL), evtMgr(NULL), layoutRequested(false), firstLayout(true), 
    sizeToFit(false), centerContent(false)
{
    if (hwnd)
        SetHwnd(hwnd);
}

HwndWrapper::~HwndWrapper()
{
    delete evtMgr;
    delete painter;
}

// Set minimum size for the HWND represented by this HwndWrapper.
// It is enforced in EventManager.
// Default size is (0,0) which is unlimited.
// For top-level windows it's the size of the whole window, including
// non-client area like borders, title area etc.
void HwndWrapper::SetMinSize(Size s)
{
    evtMgr->SetMinSize(s);
}

// Set maximum size for the HWND represented by this HwndWrapper.
// It is enforced in EventManager.
// Default size is (0,0) which is unlimited.
// For top-level windows it's the size of the whole window, including
// non-client area like borders, title area etc.
void HwndWrapper::SetMaxSize(Size s)
{
    evtMgr->SetMaxSize(s);
}

void HwndWrapper::SetHwnd(HWND hwnd)
{
    CrashIf(NULL != hwndParent);
    hwndParent = hwnd;
    evtMgr = new EventMgr(this);
    painter = new Painter(this);
}

Size HwndWrapper::Measure(const Size availableSize)
{
    if (layout) {
        return layout->Measure(availableSize);
    }
    if (children.Count() == 1) {
        ILayout *l = children.At(0);
        return l->Measure(availableSize);
    }
    desiredSize = Size();
    return desiredSize;
}

void HwndWrapper::Arrange(const Rect finalRect)
{
    if (layout) {
        // might over-write position if our layout knows about us
        layout->Arrange(finalRect);
    } else {
        if (children.Count() == 1) {
            ILayout *l = children.At(0);
            l->Arrange(finalRect);
        }
    }
}

// called when either the window size changed (as a result
// of WM_SIZE) or when the content of the window changes
void HwndWrapper::TopLevelLayout()
{
    CrashIf(!hwndParent);
    ClientRect rc(hwndParent);
    Size availableSize(rc.dx, rc.dy);
    //lf("(%3d,%3d) HwndWrapper::TopLevelLayout()", rc.dx, rc.dy);
    Size s = Measure(availableSize);

    if (firstLayout && sizeToFit) {
        firstLayout = false;
        desiredSize = s;
        ResizeHwndToClientArea(hwndParent, s.Width, s.Height, false);
    } else {
        desiredSize = availableSize;
        Rect r(0, 0, availableSize.Width, availableSize.Height);
        SetPosition(r);
        if (centerContent) {
            int n = availableSize.Width - s.Width;
            if (n > 0) {
                r.X = n / 2;
                r.Width = s.Width;
            }
            n = availableSize.Height - s.Height;
            if (n > 0) {
                r.Y = n / 2;
                r.Height = s.Height;
            }
        }
        Arrange(r);
    }
    layoutRequested = false;
}

// mark for re-layout as soon as possible
void HwndWrapper::RequestLayout()
{
    layoutRequested = true;
    repaintRequested = true;
    // trigger message queue so that the layout request is processed
    InvalidateRect(hwndParent, NULL, TRUE);
    UpdateWindow(hwndParent);
}

void HwndWrapper::LayoutIfRequested()
{
    if (layoutRequested)
        TopLevelLayout();
}

void HwndWrapper::OnPaint(HWND hwnd)
{
    CrashIf(hwnd != hwndParent);
    painter->Paint(hwnd, repaintRequested);
    repaintRequested = false;
}

}
