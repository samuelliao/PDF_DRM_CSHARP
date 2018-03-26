/* Copyright 2012 the SumatraPDF project authors (see AUTHORS file).
   License: GPLv3 */

#include "BaseUtil.h"
#include "WinUtil.h"

#include "CPdfFilter.h"
#ifdef BUILD_TEX_IFILTER
#include "CTeXFilter.h"
#endif

HINSTANCE g_hInstance = NULL;
long g_lRefCount = 0;


class CClassFactory : public IClassFactory
{
public:
    CClassFactory(REFCLSID rclsid) : m_lRef(1), m_clsid(rclsid)
    {
        InterlockedIncrement(&g_lRefCount);
    }

    ~CClassFactory() { InterlockedDecrement(&g_lRefCount); }

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 }
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_lRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&m_lRef);
        if (cRef == 0)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown *punkOuter, REFIID riid, void **ppv)
    {
        *ppv = NULL;
        if (punkOuter)
            return CLASS_E_NOAGGREGATION;

        ScopedComPtr<IFilter> pFilter;

        CLSID clsid;
        if (SUCCEEDED(CLSIDFromString(SZ_PDF_FILTER_CLSID, &clsid)) && IsEqualCLSID(m_clsid, clsid))
            pFilter = new CPdfFilter(&g_lRefCount);
#ifdef BUILD_TEX_IFILTER
        else if (SUCCEEDED(CLSIDFromString(SZ_TEX_FILTER_CLSID, &clsid)) && IsEqualCLSID(m_clsid, clsid))
            pFilter = new CTeXFilter(&g_lRefCount);
#endif
        else
            return E_NOINTERFACE;
        if (!pFilter)
            return E_OUTOFMEMORY;

        return pFilter->QueryInterface(riid, ppv);
    }

    IFACEMETHODIMP LockServer(BOOL bLock)
    {
        if (bLock)
            InterlockedIncrement(&g_lRefCount);
        else
            InterlockedDecrement(&g_lRefCount);
        return S_OK;
    }

private:
    long m_lRef;
    CLSID m_clsid;
};



STDAPI_(BOOL) DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        g_hInstance = hInstance;

    return TRUE;
}

STDAPI DllCanUnloadNow(VOID)
{
    return g_lRefCount == 0 ? S_OK : S_FALSE;
}

// disable warning C6387 which is wrongly issued due to a compiler bug; cf.
// http://connect.microsoft.com/VisualStudio/feedback/details/498862/c6387-warning-on-stock-dllgetclassobject-code-with-static-analyser
#pragma warning(push)
#pragma warning(disable: 6387) /* '*ppv' might be '0': this does not adhere to the specification for the function 'DllGetClassObject' */

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
    *ppv = NULL;
    ScopedComPtr<CClassFactory> pClassFactory(new CClassFactory(rclsid));
    if (!pClassFactory)
        return E_OUTOFMEMORY;
    return pClassFactory->QueryInterface(riid, ppv);
}

#pragma warning(pop)

STDAPI DllRegisterServer()
{
    WCHAR path[MAX_PATH];
    if (!GetModuleFileName(g_hInstance, path, dimof(path)))
        return HRESULT_FROM_WIN32(GetLastError());

    struct {
        WCHAR *key, *value, *data;
    } regVals[] = {
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_CLSID,
                NULL,                   L"SumatraPDF IFilter" },
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_CLSID L"\\InProcServer32",
                NULL,                   path },
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_CLSID L"\\InProcServer32",
                L"ThreadingModel",   L"Both" },
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_HANDLER,
                NULL,                   L"SumatraPDF IFilter Persistent Handler" },
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_HANDLER L"\\PersistentAddinsRegistered",
                NULL,                   L"" },
        { L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_HANDLER L"\\PersistentAddinsRegistered\\{89BCB740-6119-101A-BCB7-00DD010655AF}",
                NULL,                   SZ_PDF_FILTER_CLSID },
        { L"Software\\Classes\\.pdf\\PersistentHandler",
                NULL,                   SZ_PDF_FILTER_HANDLER },
#ifdef BUILD_TEX_IFILTER
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_CLSID,
                NULL,                   L"SumatraPDF IFilter" },
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_CLSID L"\\InProcServer32",
                NULL,                   path },
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_CLSID L"\\InProcServer32",
                L"ThreadingModel",      L"Both" },
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_HANDLER,
                NULL,                   L"SumatraPDF LaTeX IFilter Persistent Handler" },
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_HANDLER L"\\PersistentAddinsRegistered",
                NULL,                   L"" },
        { L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_HANDLER L"\\PersistentAddinsRegistered\\{89BCB740-6119-101A-BCB7-00DD010655AF}",
                NULL,                   SZ_TEX_FILTER_CLSID },
        { L"Software\\Classes\\.tex\\PersistentHandler",
                NULL,                   SZ_TEX_FILTER_HANDLER },
#endif
    };

    for (int i = 0; i < dimof(regVals); i++) {
        WriteRegStr(HKEY_LOCAL_MACHINE, regVals[i].key, regVals[i].value, regVals[i].data);
        bool ok = WriteRegStr(HKEY_CURRENT_USER, regVals[i].key, regVals[i].value, regVals[i].data);
        if (!ok)
            return E_FAIL;
    }

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    const WCHAR *regKeys[] = {
        L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_CLSID,
        L"Software\\Classes\\CLSID\\" SZ_PDF_FILTER_HANDLER,
        L"Software\\Classes\\.pdf\\PersistentHandler"
#ifdef BUILD_TEX_IFILTER
        L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_CLSID,
        L"Software\\Classes\\CLSID\\" SZ_TEX_FILTER_HANDLER,
        L"Software\\Classes\\.tex\\PersistentHandler",
#endif
    };

    HRESULT hr = S_OK;

    for (int i = 0; i < dimof(regKeys); i++) {
        DeleteRegKey(HKEY_LOCAL_MACHINE, regKeys[i]);
        bool ok = DeleteRegKey(HKEY_CURRENT_USER, regKeys[i]);
        if (!ok)
            hr = E_FAIL;
    }

    return hr;
}

#ifdef _WIN64
#pragma comment(linker, "/EXPORT:DllCanUnloadNow=DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/EXPORT:DllGetClassObject=DllGetClassObject,PRIVATE")
#pragma comment(linker, "/EXPORT:DllRegisterServer=DllRegisterServer,PRIVATE")
#pragma comment(linker, "/EXPORT:DllUnregisterServer=DllUnregisterServer,PRIVATE")
#else
#pragma comment(linker, "/EXPORT:DllCanUnloadNow=_DllCanUnloadNow@0,PRIVATE")
#pragma comment(linker, "/EXPORT:DllGetClassObject=_DllGetClassObject@12,PRIVATE")
#pragma comment(linker, "/EXPORT:DllRegisterServer=_DllRegisterServer@0,PRIVATE")
#pragma comment(linker, "/EXPORT:DllUnregisterServer=_DllUnregisterServer@0,PRIVATE")
#endif
