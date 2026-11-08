#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <winhttp.h>
#include <fwpmu.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#pragma comment(lib,"fwpuclnt.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"rpcrt4.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"winhttp.lib")
// Own provider and sublayer only. No global firewall profile, service, or existing rule edits.
static const GUID Provider={0x4c133ed2,0x827b,0x4e6a,{0xb9,0xd4,0x13,0x84,0x91,0x78,0x98,0x21}};
static const GUID Sublayer={0x73c0edc6,0x0d81,0x4d09,{0xa8,0x78,0x53,0x62,0xae,0x78,0x98,0x21}};
static void check(DWORD e,const char* where){if(e)throw std::runtime_error(std::string(where)+" error="+std::to_string(e));}
struct Engine {HANDLE h=nullptr; Engine(){check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&h),"FwpmEngineOpen");}~Engine(){if(h)FwpmEngineClose0(h);}};
struct Tx {HANDLE h;bool committed=false;Tx(HANDLE x):h(x){check(FwpmTransactionBegin0(h,0),"TransactionBegin");}~Tx(){if(!committed)FwpmTransactionAbort0(h);}void commit(){check(FwpmTransactionCommit0(h),"TransactionCommit");committed=true;}};
struct Blob {FWP_BYTE_BLOB* p=nullptr;Blob(const std::wstring& path){check(FwpmGetAppIdFromFileName0(path.c_str(),&p),"AppId");}~Blob(){if(p)FwpmFreeMemory0((void**)&p);}};
static std::wstring fullpath(const wchar_t* value){wchar_t out[32768];DWORD n=GetFullPathNameW(value,32768,out,nullptr);if(!n||n>=32768)throw std::runtime_error("Invalid path");return out;}
struct Entry {GUID key;std::wstring path;UINT64 id;};
static std::vector<Entry> entries(HANDLE h){
  FWPM_PROVIDER0* provider=nullptr;DWORD found=FwpmProviderGetByKey0(h,&Provider,&provider);if(found==FWP_E_PROVIDER_NOT_FOUND)return {};check(found,"ProviderGet");FwpmFreeMemory0((void**)&provider);
  HANDLE e=nullptr;
  check(FwpmFilterCreateEnumHandle0(h,nullptr,&e),"EnumHandle");std::vector<Entry> out;
  try{for(;;){FWPM_FILTER0** rows=nullptr;UINT32 n=0;check(FwpmFilterEnum0(h,e,128,&rows,&n),"FilterEnum");for(UINT32 i=0;i<n;i++)if(rows[i]->providerKey && IsEqualGUID(*rows[i]->providerKey,Provider))out.push_back({rows[i]->filterKey,rows[i]->displayData.description?rows[i]->displayData.description:L"",rows[i]->filterId});if(rows)FwpmFreeMemory0((void**)&rows);if(n<128)break;}}catch(...){FwpmFilterDestroyEnumHandle0(h,e);throw;}
  FwpmFilterDestroyEnumHandle0(h,e);return out;
}
static void setup(HANDLE h){
  FWPM_PROVIDER0 p={};p.providerKey=Provider;p.displayData.name=(wchar_t*)L"Claude 7898 Local Guard";p.flags=FWPM_PROVIDER_FLAG_PERSISTENT;
  DWORD r=FwpmProviderAdd0(h,&p,nullptr);if(r!=FWP_E_ALREADY_EXISTS)check(r,"ProviderAdd");
  FWPM_SUBLAYER0 s={};s.subLayerKey=Sublayer;s.displayData.name=(wchar_t*)L"Claude 7898 application-scoped restrictions";s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;s.providerKey=(GUID*)&Provider;s.weight=0x9000;
  r=FwpmSubLayerAdd0(h,&s,nullptr);if(r!=FWP_E_ALREADY_EXISTS)check(r,"SubLayerAdd");
}
static void removePath(HANDLE h,const std::wstring& path){for(auto& x:entries(h))if(!_wcsicmp(x.path.c_str(),path.c_str()))check(FwpmFilterDeleteByKey0(h,&x.key),"FilterDelete");}
static void add(HANDLE h,const std::wstring& path){
  if(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES)throw std::runtime_error("Executable missing");
  Blob app(path);removePath(h,path);
  for(int kind=0;kind<4;kind++){
    FWPM_FILTER_CONDITION0 c[2]={};c[0].fieldKey=FWPM_CONDITION_ALE_APP_ID;c[0].matchType=FWP_MATCH_EQUAL;c[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[0].conditionValue.byteBlob=app.p;
    if(kind==0){c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[1].matchType=FWP_MATCH_NOT_EQUAL;c[1].conditionValue.type=FWP_UINT32;c[1].conditionValue.uint32=0x7f000001;}
    if(kind==1){c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;c[1].matchType=FWP_MATCH_NOT_EQUAL;c[1].conditionValue.type=FWP_UINT16;c[1].conditionValue.uint16=7898;}
    if(kind==2){c[1].fieldKey=FWPM_CONDITION_IP_PROTOCOL;c[1].matchType=FWP_MATCH_NOT_EQUAL;c[1].conditionValue.type=FWP_UINT8;c[1].conditionValue.uint8=IPPROTO_TCP;}
    FWPM_FILTER0 f={};check(CoCreateGuid(&f.filterKey),"CreateGuid");
    std::wstring label=L"Claude7898: "+std::to_wstring(kind)+L" "+path;
    f.displayData.name=(wchar_t*)label.c_str();f.displayData.description=(wchar_t*)path.c_str();f.flags=FWPM_FILTER_FLAG_PERSISTENT;f.providerKey=(GUID*)&Provider;
    f.layerKey=kind==3?FWPM_LAYER_ALE_AUTH_CONNECT_V6:FWPM_LAYER_ALE_AUTH_CONNECT_V4;f.subLayerKey=Sublayer;f.weight.type=FWP_EMPTY;f.action.type=FWP_ACTION_BLOCK;
    f.numFilterConditions=kind==3?1:2;f.filterCondition=c;UINT64 id;check(FwpmFilterAdd0(h,&f,nullptr,&id),"FilterAdd");
  }
}
static bool exactRule(HANDLE h,const Entry& entry,const std::wstring& path,int kind){
  FWPM_FILTER0* f=nullptr;check(FwpmFilterGetByKey0(h,&entry.key,&f),"FilterReadback");
  Blob app(path);bool ok=f->action.type==FWP_ACTION_BLOCK &&
    IsEqualGUID(f->layerKey,kind==3?FWPM_LAYER_ALE_AUTH_CONNECT_V6:FWPM_LAYER_ALE_AUTH_CONNECT_V4) &&
    IsEqualGUID(f->subLayerKey,Sublayer) && (f->flags&FWPM_FILTER_FLAG_PERSISTENT) &&
    f->numFilterConditions==(kind==3?1u:2u);
  bool hasApp=false,hasConstraint=kind==3;
  for(UINT32 i=0;ok && i<f->numFilterConditions;i++){
    const auto& c=f->filterCondition[i];
    if(IsEqualGUID(c.fieldKey,FWPM_CONDITION_ALE_APP_ID)){
      hasApp=c.matchType==FWP_MATCH_EQUAL && c.conditionValue.type==FWP_BYTE_BLOB_TYPE &&
        c.conditionValue.byteBlob->size==app.p->size &&
        memcmp(c.conditionValue.byteBlob->data,app.p->data,app.p->size)==0;
    }else if(kind==0 && IsEqualGUID(c.fieldKey,FWPM_CONDITION_IP_REMOTE_ADDRESS))
      hasConstraint=c.matchType==FWP_MATCH_NOT_EQUAL && c.conditionValue.type==FWP_UINT32 && c.conditionValue.uint32==0x7f000001;
    else if(kind==1 && IsEqualGUID(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT))
      hasConstraint=c.matchType==FWP_MATCH_NOT_EQUAL && c.conditionValue.type==FWP_UINT16 && c.conditionValue.uint16==7898;
    else if(kind==2 && IsEqualGUID(c.fieldKey,FWPM_CONDITION_IP_PROTOCOL))
      hasConstraint=c.matchType==FWP_MATCH_NOT_EQUAL && c.conditionValue.type==FWP_UINT8 && c.conditionValue.uint8==IPPROTO_TCP;
    else ok=false;
  }
  FwpmFreeMemory0((void**)&f);return ok && hasApp && hasConstraint;
}
static void verify(HANDLE h,const std::wstring& path){
  auto all=entries(h);std::vector<Entry> matching;for(auto& x:all)if(!_wcsicmp(x.path.c_str(),path.c_str()))matching.push_back(x);
  if(matching.size()!=4)throw std::runtime_error("Expected four application filters");
  for(int kind=0;kind<4;kind++)if(std::count_if(matching.begin(),matching.end(),[&](const Entry& x){return exactRule(h,x,path,kind);})!=1)
    throw std::runtime_error("Filter conditions differ from TCP 127.0.0.1:7898 contract");
  std::wcout<<L"VERIFIED TCP 127.0.0.1:7898 ONLY\t"<<path<<L"\n";
}
static int probe(const wchar_t* address,const wchar_t* port,bool udp){
  WSADATA data;check(WSAStartup(MAKEWORD(2,2),&data),"WSAStartup");
  ADDRINFOW hints={};hints.ai_flags=AI_NUMERICHOST|AI_NUMERICSERV;hints.ai_family=AF_UNSPEC;hints.ai_socktype=udp?SOCK_DGRAM:SOCK_STREAM;ADDRINFOW* ai=nullptr;
  check(GetAddrInfoW(address,port,&hints,&ai),"NumericAddress");SOCKET s=socket(ai->ai_family,ai->ai_socktype,udp?IPPROTO_UDP:IPPROTO_TCP);if(s==INVALID_SOCKET)throw std::runtime_error("socket failed");
  u_long nb=1;ioctlsocket(s,FIONBIO,&nb);int r=connect(s,ai->ai_addr,(int)ai->ai_addrlen);int e=r?WSAGetLastError():0;
  if(e==WSAEWOULDBLOCK){fd_set w,x;FD_ZERO(&w);FD_ZERO(&x);FD_SET(s,&w);FD_SET(s,&x);timeval timeout={4,0};r=select(0,nullptr,&w,&x,&timeout);if(r>0){int size=sizeof(e);getsockopt(s,SOL_SOCKET,SO_ERROR,(char*)&e,&size);}else e=r==0?WSAETIMEDOUT:WSAGetLastError();}
  if(!e && udp){char b=0;int sent=send(s,&b,1,0);if(sent==SOCKET_ERROR)e=WSAGetLastError();}
  std::wcout<<address<<L":"<<port<<L" "<<(udp?L"UDP":L"TCP")<<L" error="<<e<<L"\n";closesocket(s);FreeAddrInfoW(ai);WSACleanup();return e==0?0:e==WSAEACCES?13:2;
}
static int proxyCheck(){
  // No account, cookies, credentials, or Anthropic endpoints. TLS validation remains enabled.
  HINTERNET session=WinHttpOpen(L"ClaudeGuard-ConnectivityTest/1.0",WINHTTP_ACCESS_TYPE_NAMED_PROXY,L"127.0.0.1:7898",WINHTTP_NO_PROXY_BYPASS,0);
  if(!session){std::cout<<"WinHttpOpen error="<<GetLastError()<<"\n";return 2;}
  WinHttpSetTimeouts(session,3000,4000,6000,6000);
  HINTERNET connection=WinHttpConnect(session,L"www.cloudflare.com",443,0);
  HINTERNET request=connection?WinHttpOpenRequest(connection,L"GET",L"/cdn-cgi/trace",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE):nullptr;
  DWORD err=0,status=0,size=sizeof(status);
  if(!request || !WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) || !WinHttpReceiveResponse(request,nullptr))err=GetLastError();
  else if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX))err=GetLastError();
  if(request)WinHttpCloseHandle(request);if(connection)WinHttpCloseHandle(connection);WinHttpCloseHandle(session);
  std::cout<<"proxy=127.0.0.1:7898 destination=www.cloudflare.com TLS_validated=true status="<<status<<" error="<<err<<"\n";return !err && status==200?0:2;
}
int wmain(int argc,wchar_t** argv){try{
  if(argc==2 && !wcscmp(argv[1],L"proxycheck"))return proxyCheck();
  if(argc>=4 && !wcscmp(argv[1],L"probe"))return probe(argv[2],argv[3],argc==5 && !wcscmp(argv[4],L"udp"));
  if(argc<2)throw std::runtime_error("Usage: status | add path... | remove path... | remove-all | probe numeric-ip port [udp]");
  Engine e;std::wstring mode=argv[1];
  if(mode==L"status"){for(auto& x:entries(e.h))std::wcout<<x.id<<L"\t"<<x.path<<L"\n";return 0;}
  if(mode==L"verify" && argc>2){for(int i=2;i<argc;i++)verify(e.h,fullpath(argv[i]));return 0;}
  Tx tx(e.h);
  if(mode==L"add" && argc>2){setup(e.h);for(int i=2;i<argc;i++)add(e.h,fullpath(argv[i]));}
  else if(mode==L"remove" && argc>2){for(int i=2;i<argc;i++)removePath(e.h,fullpath(argv[i]));}
  else if(mode==L"remove-all"){for(auto& x:entries(e.h))check(FwpmFilterDeleteByKey0(e.h,&x.key),"FilterDelete");DWORD r=FwpmSubLayerDeleteByKey0(e.h,&Sublayer);if(r!=FWP_E_SUBLAYER_NOT_FOUND)check(r,"SubLayerDelete");r=FwpmProviderDeleteByKey0(e.h,&Provider);if(r!=FWP_E_PROVIDER_NOT_FOUND)check(r,"ProviderDelete");}
  else throw std::runtime_error("Invalid operation");
  tx.commit();std::cout<<"Committed application-scoped operation.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
