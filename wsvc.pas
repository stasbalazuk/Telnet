program wsvc;

{$DEFINE SERVICE_DEBUG}

uses
  Windows,
  SysUtils,
  WinSvc;

const
  InfoStr = 'Use:'#13#10'%s [ -install | -uninstall ]';
  ServiceFileName = 'wsvc.exe';
  FirstName = 'wsvcsts';
  FirstDisplayName = 'Test STS First';    //��� ������� �������
  SecondName = 'stswsvc';
  SecondDisplayName = 'Test STS To';  //��� ������� �������
  FirstContext = 1;
  SecondContext = 2;

type
  LPHANDLER_FUNCTION_EX = function (dwControl, dwEventType: DWORD;
    lpEventData, lpContext: Pointer): DWORD; stdcall;
  THandlerFunctionEx = LPHANDLER_FUNCTION_EX;

  function RegisterServiceCtrlHandlerEx(lpServiceName: LPCWSTR;
    lpHandlerProc: LPHANDLER_FUNCTION_EX; lpContext: Pointer):
    SERVICE_STATUS_HANDLE; stdcall; external 'advapi32.dll' name 'RegisterServiceCtrlHandlerExW';
    
var
  ServicesTable: packed array [0..2] of TServiceTableEntry;
  FirstStatusHandle: SERVICE_STATUS_HANDLE = 0;
  SecondStatusHandle: SERVICE_STATUS_HANDLE = 0;
  FirstStatus: TServiceStatus;
  SecondStatus: TServiceStatus;

{$R *.res}

// ** ��������� ��������� � ������� ********************************************

// ����� ���������� (��� ������ ������� �� �����������)
procedure ShowMsg(Msg: string; Flags: integer = -1);
begin
  if Flags < 0 then Flags := MB_ICONSTOP;
  MessageBox(0, PChar(Msg), ServiceFileName, MB_OK or MB_TASKMODAL or MB_TOPMOST or Flags)
end;

// ���������� �������� � SCM
function Install: Boolean;
const
  StartType =
{$IFDEF SERVICE_DEBUG}
    SERVICE_DEMAND_START;
{$ELSE}
    SERVICE_AUTO_START;
{$ENDIF}
var
  SCManager, Service: SC_HANDLE;
begin
  SCManager := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if SCManager <> 0 then
  try
    // ����������� ������ ������
    Service := CreateService(SCManager, FirstName, FirstDisplayName, SERVICE_ALL_ACCESS,
      SERVICE_WIN32_SHARE_PROCESS or SERVICE_INTERACTIVE_PROCESS, StartType, SERVICE_ERROR_NORMAL,
      PChar('"' + ParamStr(0) + '" -service'), nil, nil, nil, nil, nil);
    if Service <> 0 then
    try
      Result := ChangeServiceConfig(Service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, nil, nil,
        nil, nil, nil, nil, nil);
    finally
      CloseServiceHandle(Service);
    end
    else
      Result := GetLastError = ERROR_SERVICE_EXISTS;

    // ����������� ������ ������
    Service := CreateService(SCManager, SecondName, SecondDisplayName, SERVICE_ALL_ACCESS,
      SERVICE_WIN32_SHARE_PROCESS or SERVICE_INTERACTIVE_PROCESS, StartType, SERVICE_ERROR_NORMAL,
      PChar('"' + ParamStr(0) + '" -service'), nil, nil, nil, nil, nil);
    if Service <> 0 then
    try
      Result := ChangeServiceConfig(Service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, nil, nil,
        nil, nil, nil, nil, nil);
    finally
      CloseServiceHandle(Service);
    end
    else
      Result := GetLastError = ERROR_SERVICE_EXISTS;

  finally
    CloseServiceHandle(SCManager);
  end
  else
    Result := False;
end;

// ������������ �������� � SCM
function Uninstall: Boolean;
var
  SCManager, Service: SC_HANDLE;
begin
  SCManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if SCManager <> 0 then
  try
    // ������� ������ ������
    Service := OpenService(SCManager, FirstName, _DELETE);
    if Service <> 0 then
    try
      Result := DeleteService(Service);
    finally
      CloseServiceHandle(Service);
    end
    else
      Result := GetLastError = ERROR_SERVICE_DOES_NOT_EXIST;

    // ������� ������ ������
    Service := OpenService(SCManager, SecondName, _DELETE);
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

// *** ��������������� ������ �������� *****************************************

// ������������� ������� �������
function FirstInitialize: Boolean;
begin
  with FirstStatus do
  begin
    dwServiceType := SERVICE_WIN32_SHARE_PROCESS;
    dwCurrentState := SERVICE_START_PENDING;
    dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
    dwWin32ExitCode := NO_ERROR;
    dwServiceSpecificExitCode := 0;
    dwCheckPoint := 1;
    dwWaitHint := 5000
  end;
  Result := SetServiceStatus(FirstStatusHandle, FirstStatus);
end;

// ���������� SCM ��� ������ ������ ��������
function FirstNotifyIsRunning: Boolean;
begin
  with FirstStatus do
  begin
    dwCurrentState := SERVICE_RUNNING;
    dwWin32ExitCode := NO_ERROR;
    dwCheckPoint := 0;
    dwWaitHint := 0
  end;
  Result := SetServiceStatus(FirstStatusHandle, FirstStatus);
end;

// ���������� ������ ������� �������
procedure FirstStop(Code: DWORD = NO_ERROR);
begin
  with FirstStatus do
  begin
    dwCurrentState := SERVICE_STOPPED;
    dwWin32ExitCode := Code;
  end;
  SetServiceStatus(FirstStatusHandle, FirstStatus); // ����������� True - ��������
end;

// ������������� ������� �������
function SecondInitialize: Boolean;
begin
  with SecondStatus do
  begin
    dwServiceType := SERVICE_WIN32_SHARE_PROCESS;
    dwCurrentState := SERVICE_START_PENDING;
    dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
    dwWin32ExitCode := NO_ERROR;
    dwServiceSpecificExitCode := 0;
    dwCheckPoint := 1;
    dwWaitHint := 5000
  end;
  Result := SetServiceStatus(SecondStatusHandle, SecondStatus);
end;

// ���������� SCM ��� ������ ������ ��������
function SecondNotifyIsRunning: Boolean;
begin
  with SecondStatus do
  begin
    dwCurrentState := SERVICE_RUNNING;
    dwWin32ExitCode := NO_ERROR;
    dwCheckPoint := 0;
    dwWaitHint := 0
  end;
  Result := SetServiceStatus(SecondStatusHandle, SecondStatus);
end;

// ���������� ������ ������� �������
procedure SecondStop(Code: DWORD = NO_ERROR);
begin
  with SecondStatus do
  begin
    dwCurrentState := SERVICE_STOPPED;
    dwWin32ExitCode := Code;
  end;
  SetServiceStatus(SecondStatusHandle, SecondStatus); // ����������� True - ��������
end;

// ����� ��� ������� � ������ ��������� �������� SCM
function ServicesCtrlHandler(dwControl, dwEventType: DWORD;
  lpEventData, lpContext: Pointer): DWORD; stdcall;
begin
  Result := 1;
  case DWORD(lpContext^) of
    FirstContext:
    begin
      case dwControl of
        SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
          FirstStop;
        SERVICE_CONTROL_INTERROGATE:
          FirstNotifyIsRunning;
      end;
    end;
    SecondContext:
    begin
      case dwControl of
        SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
          SecondStop;
        SERVICE_CONTROL_INTERROGATE:
          SecondNotifyIsRunning;
      end;
    end;
  end;
end;

// ������� ��������� ������� �������
procedure FirstMainProc(ArgCount: DWORD; var Args: array of PChar); stdcall;
var
  Context: DWORD;
begin
    if FileExists('c:\TEMP\readme.txt') then
      WinExec('c:\TEMP\readme.txt',SW_SHOW);  
  Context := FirstContext;
  FirstStatusHandle := RegisterServiceCtrlHandlerEx(FirstName,
    @ServicesCtrlHandler, @Context);
  if (FirstStatusHandle <> 0) and FirstInitialize and FirstNotifyIsRunning then
    while FirstStatus.dwCurrentState <> SERVICE_STOP do
    try
      // ���������� ������ �������
      Sleep(10);
    except
      // ��������� ������ �������
    end;
  ExitThread(0);
end;

// ������� ��������� ������� �������
procedure SecondMainProc(ArgCount: DWORD; var Args: array of PChar); stdcall;
var
  Context: DWORD;
begin
  Context := SecondContext;
  SecondStatusHandle := RegisterServiceCtrlHandlerEx(SecondName,
    @ServicesCtrlHandler, @Context);
  if (SecondStatusHandle <> 0) and SecondInitialize and SecondNotifyIsRunning then
    while SecondStatus.dwCurrentState <> SERVICE_STOP do
    try
      // ���������� ������ �������
      Sleep(10);
    except
      // ��������� ������ �������
    end;
  ExitThread(0);
end;

// Main
begin
  if ParamCount > 0 then
  begin
    // ����������
    if AnsiUpperCase(ParamStr(1)) = '-INSTALL' then
    begin
      if not Install then ShowMsg(SysErrorMessage(GetLastError));
      Exit;
    end;
    // ������������
    if AnsiUpperCase(ParamStr(1)) = '-UNINSTALL' then
    begin
      if not Uninstall then ShowMsg(SysErrorMessage(GetLastError));
      Exit;
    end;
    // ������ ��������
    if AnsiUpperCase(ParamStr(1)) = '-SERVICE' then
    begin
      ServicesTable[0].lpServiceName := FirstName;
      ServicesTable[0].lpServiceProc := @FirstMainProc;
      ServicesTable[1].lpServiceName := SecondName;
      ServicesTable[1].lpServiceProc := @SecondMainProc;
      ServicesTable[2].lpServiceName := nil;
      ServicesTable[2].lpServiceProc := nil;
      // ��������� �������, ������ ������ ���� � �� ������� ����������
      if not StartServiceCtrlDispatcher(ServicesTable[0]) and
        (GetLastError <> ERROR_SERVICE_ALREADY_RUNNING) then
          ShowMsg(SysErrorMessage(GetLastError));
    end
    else
      ShowMsg(Format(InfoStr, [ServiceFileName]), MB_ICONINFORMATION);
  end
  else
    ShowMsg(Format(InfoStr, [ServiceFileName]), MB_ICONINFORMATION);
end.
