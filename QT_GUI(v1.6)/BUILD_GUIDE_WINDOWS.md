# Windows 빌드 가이드

이 가이드는 Windows에서 Qt GUI 애플리케이션을 빌드하는 방법을 상세히 설명합니다.

## 📋 사전 준비사항

### 1. vcpkg 설치 및 설정

vcpkg는 Windows용 C++ 패키지 관리자입니다. OpenSSL을 설치하기 위해 필요합니다.

#### vcpkg 설치

1. **vcpkg 다운로드:**
```cmd
cd C:\Users\sihwa\source\repos
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
```

2. **vcpkg 부트스트랩:**
```cmd
.\bootstrap-vcpkg.bat
```

3. **OpenSSL 설치:**
```cmd
.\vcpkg install openssl:x64-windows
```

#### 환경 변수 설정

**시스템 환경 변수 설정 (영구적, 권장):**

1. Windows 검색에서 "환경 변수" 입력 → "시스템 환경 변수 편집" 선택
2. "환경 변수" 버튼 클릭
3. "시스템 변수" 섹션에서 "새로 만들기" 클릭
4. 변수 이름: `VCPKG_ROOT`
5. 변수 값: vcpkg 설치 경로 (예: `C:\Users\sihwa\source\repos\vcpkg`)
6. "확인" 클릭
7. **모든 창 닫기 후 Qt Creator 재시작** (환경 변수 적용을 위해)

**확인 방법:**
```cmd
echo %VCPKG_ROOT%
```

### 2. 필수 패키지 설치

#### Qt 6 설치

1. [Qt 공식 웹사이트](https://www.qt.io/download)에서 Qt 설치 프로그램 다운로드
2. Qt Online Installer 실행
3. Qt 계정 생성 또는 로그인
4. Qt 6.x 버전 선택 (예: Qt 6.5.0, Qt 6.10.1)
5. 컴파일러 선택:
   - **Visual Studio 사용 시**: MSVC 2019 64-bit 또는 MSVC 2022 64-bit
   - **MinGW 사용 시**: MinGW 11.2.0 64-bit
6. Qt Creator도 함께 설치 (권장)
7. 설치 경로 확인 (예: `C:\Qt\6.10.1\msvc2019_64`)

#### CMake 설치

1. [CMake 공식 웹사이트](https://cmake.org/download/)에서 설치 프로그램 다운로드
2. Windows x64 Installer 선택
3. 설치 시 **"Add CMake to system PATH"** 옵션 반드시 선택
4. 설치 완료

**확인 방법:**
```cmd
cmake --version
```

#### 컴파일러 설치

**옵션 1: Visual Studio (권장)**

1. [Visual Studio 공식 웹사이트](https://visualstudio.microsoft.com/)에서 다운로드
2. Visual Studio 2019 또는 2022 Community Edition 설치 (무료)
3. 설치 시 "Desktop development with C++" 워크로드 선택
4. 설치 완료

**옵션 2: MinGW**

- Qt 설치 시 함께 설치되거나
- [MinGW-w64](https://www.mingw-w64.org/)에서 별도 설치

### 3. 설치 확인

다음 명령어로 설치가 제대로 되었는지 확인하세요:

```cmd
REM Qt 경로 확인
dir C:\Qt

REM CMake 확인
cmake --version

REM vcpkg 확인
echo %VCPKG_ROOT%

REM 컴파일러 확인 (Visual Studio)
cl
REM 또는 (MinGW)
gcc --version
```

## 🔨 빌드 방법

### 방법 1: 명령 프롬프트 (CMD) 또는 PowerShell에서 빌드

#### 1단계: 프로젝트 폴더로 이동

**CMD:**
```cmd
cd C:\Users\sihwa\source\repos\QT_GUI(v1.4)
```

**PowerShell:**
```powershell
cd C:\Users\sihwa\source\repos\QT_GUI(v1.4)
```

#### 2단계: 빌드 폴더 생성

```cmd
mkdir build
cd build
```

#### 3단계: Qt 경로 확인

Qt 설치 경로를 확인하세요:
- 일반적인 경로: `C:\Qt\6.10.1\msvc2019_64` 또는 `C:\Qt\6.10.1\mingw_64`
- 실제 설치 경로에 맞게 수정하세요

**경로 확인 방법:**
```cmd
dir C:\Qt
```

#### 4단계: CMake 실행

**Visual Studio 사용 시:**
```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
```

**MinGW 사용 시:**
```cmd
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\mingw_64"
```

#### 5단계: 빌드

**Visual Studio 사용 시:**
```cmd
cmake --build . --config Release
```

**MinGW 사용 시:**
```cmd
cmake --build . --config Release
```

또는:
```cmd
mingw32-make -j%NUMBER_OF_PROCESSORS%
```

#### 6단계: 실행

```cmd
.\Release\FileCryptoGUI.exe
```

또는 파일 탐색기에서 `build\Release\FileCryptoGUI.exe` 더블클릭

### 방법 2: Qt Creator에서 빌드

#### 1단계: Qt Creator 실행

- Qt 설치 시 함께 설치된 Qt Creator 사용
- 또는 [Qt 공식 웹사이트](https://www.qt.io/download)에서 별도 다운로드

#### 2단계: 프로젝트 열기

1. Qt Creator 실행
2. "Open Project" 또는 "File → Open File or Project"
3. 프로젝트 폴더의 `CMakeLists.txt` 파일 선택

#### 3단계: 빌드 설정

1. 왼쪽 "프로젝트" 탭 클릭
2. "Build" 섹션에서 "Build Environment" 확장
3. 환경 변수 확인:
   - `VCPKG_ROOT`가 설정되어 있는지 확인
   - 없으면 "변수 추가" 클릭하여 추가
4. CMake 설정:
   - "CMake" 섹션에서 "CMAKE_PREFIX_PATH" 확인
   - Qt 경로가 올바르게 설정되어 있는지 확인 (예: `C:\Qt\6.10.1\msvc2019_64`)

#### 4단계: 빌드 및 실행

1. 하단 "Build" 버튼 클릭 또는 `Ctrl+B`
2. 빌드 완료 후 "Run" 버튼 클릭 또는 `Ctrl+R`

### 방법 3: Visual Studio에서 직접 빌드

#### 1단계: CMake GUI 실행

1. CMake GUI 실행 (시작 메뉴에서 검색)
2. "Browse Source"에서 프로젝트 폴더 선택
3. "Browse Build"에서 `build` 폴더 선택

#### 2단계: CMake 설정

1. "Configure" 버튼 클릭
2. 컴파일러 선택:
   - Visual Studio 2019 또는 2022 선택
3. "CMAKE_PREFIX_PATH"에 Qt 경로 입력 (예: `C:\Qt\6.10.1\msvc2019_64`)
4. "Generate" 버튼 클릭

#### 3단계: Visual Studio에서 빌드

1. "Open Project" 버튼 클릭하여 Visual Studio에서 열기
2. Visual Studio에서 빌드:
   - 상단 메뉴: "Build → Build Solution" 또는 `F7`
   - 또는 `Ctrl+Shift+B`
3. 실행:
   - 상단 메뉴: "Debug → Start Without Debugging" 또는 `Ctrl+F5`

## 🐛 문제 해결

### "Qt6 not found" 오류

**해결 방법:**

1. **Qt 설치 경로 확인:**
```cmd
dir C:\Qt
```

2. **정확한 경로로 다시 시도:**
```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
```

3. **환경 변수로 설정:**
```cmd
set CMAKE_PREFIX_PATH=C:\Qt\6.10.1\msvc2019_64
cmake ..
```

4. **CMake 캐시 삭제 후 재시도:**
```cmd
rmdir /s /q build
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
```

### "OpenSSL not found" 오류

**해결 방법:**

1. **vcpkg 환경 변수 확인:**
```cmd
echo %VCPKG_ROOT%
```

2. **vcpkg 환경 변수가 없으면 설정:**
   - 시스템 환경 변수에 `VCPKG_ROOT` 추가
   - Qt Creator 재시작

3. **vcpkg OpenSSL 설치 확인:**
```cmd
cd %VCPKG_ROOT%
.\vcpkg list openssl
```

4. **OpenSSL 재설치:**
```cmd
.\vcpkg install openssl:x64-windows
```

### "VCPKG_ROOT not found" 오류

**해결 방법:**

1. **환경 변수 설정 확인:**
   - 시스템 환경 변수에 `VCPKG_ROOT`가 설정되어 있는지 확인
   - 설정되어 있다면 Qt Creator 재시작

2. **임시로 설정 (현재 세션만):**
```cmd
set VCPKG_ROOT=C:\Users\sihwa\source\repos\vcpkg
```

3. **영구적으로 설정:**
   - 시스템 환경 변수에 추가 (위의 "환경 변수 설정" 참고)

### "CMake not found" 오류

**해결 방법:**

1. **CMake 설치 확인:**
```cmd
cmake --version
```

2. **PATH에 CMake가 없으면:**
   - CMake 재설치 시 "Add CMake to system PATH" 옵션 선택
   - 또는 수동으로 PATH에 추가:
     - 예: `C:\Program Files\CMake\bin`

3. **전체 경로로 실행:**
```cmd
"C:\Program Files\CMake\bin\cmake.exe" --version
```

### "Visual Studio not found" 오류

**해결 방법:**

1. **Visual Studio 설치 확인:**
   - Visual Studio Installer 실행
   - "Desktop development with C++" 워크로드가 설치되어 있는지 확인

2. **Developer Command Prompt 사용:**
   - Visual Studio의 "Developer Command Prompt for VS 2019/2022" 사용
   - 또는 일반 명령 프롬프트에서:
```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

### "undefined reference" 링크 오류

**해결 방법:**

1. **BUILD_GUI 정의 확인:**
   - CMakeLists.txt에 `BUILD_GUI`가 정의되어 있는지 확인
   - `cli.c`의 `main` 함수가 컴파일되지 않아야 함

2. **빌드 폴더 완전히 삭제 후 재빌드:**
```cmd
rmdir /s /q build
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
cmake --build . --config Release
```

### "Permission denied" 오류

**해결 방법:**

1. **관리자 권한으로 실행:**
   - 명령 프롬프트를 관리자 권한으로 실행
   - 또는 Qt Creator를 관리자 권한으로 실행

2. **파일 권한 확인:**
   - 빌드 폴더에 쓰기 권한이 있는지 확인

## 📝 빠른 참조

### 전체 빌드 명령어 (한 번에)

**Visual Studio 사용 시 (CMD):**
```cmd
cd C:\Users\sihwa\source\repos\QT_GUI(v1.4)
if not exist build mkdir build
cd build
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
cmake --build . --config Release
.\Release\FileCryptoGUI.exe
```

**Visual Studio 사용 시 (PowerShell):**
```powershell
cd C:\Users\sihwa\source\repos\QT_GUI(v1.4)
if (-not (Test-Path build)) { New-Item -ItemType Directory -Path build }
cd build
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64"
cmake --build . --config Release
.\Release\FileCryptoGUI.exe
```

**MinGW 사용 시:**
```cmd
cd C:\Users\sihwa\source\repos\QT_GUI(v1.4)
if not exist build mkdir build
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\mingw_64"
cmake --build . --config Release
.\Release\FileCryptoGUI.exe
```

## ✅ 빌드 성공 확인

빌드가 성공하면:
- `build\Release\FileCryptoGUI.exe` 파일이 생성됩니다
- 실행: 더블클릭하거나 명령줄에서 `.\Release\FileCryptoGUI.exe`

## 🔍 빌드 출력 위치

- **실행 파일**: `build\Release\FileCryptoGUI.exe`
- **디버그 빌드**: `build\Debug\FileCryptoGUI.exe`
- **오브젝트 파일**: `build\Release\CMakeFiles\...`

## 📌 중요 참고사항

1. **환경 변수:**
   - `VCPKG_ROOT`: vcpkg 설치 경로 (필수)
   - `CMAKE_PREFIX_PATH`: Qt 설치 경로 (CMake 실행 시 지정)
   - 환경 변수 설정 후 Qt Creator 재시작 필요

2. **컴파일러 선택:**
   - Visual Studio: MSVC 컴파일러 사용
   - MinGW: GCC 컴파일러 사용
   - Qt 설치 시 선택한 컴파일러와 일치해야 함

3. **경로 주의사항:**
   - Windows 경로는 백슬래시(`\`) 사용
   - 경로에 공백이 있으면 따옴표로 감싸기
   - 예: `"C:\Program Files\Qt\..."`

4. **터미널:**
   - 이 가이드의 "터미널"은 Windows 명령 프롬프트(CMD) 또는 PowerShell을 의미합니다
   - Qt Creator 내부 터미널도 사용 가능하지만, 일반적으로 Windows 터미널을 사용합니다

## 🚀 추가 팁

### 디버그 빌드

```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64" -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
```

### 병렬 빌드 (빠른 빌드)

```cmd
cmake --build . --config Release --parallel %NUMBER_OF_PROCESSORS%
```

### 빌드 정보 확인

```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.10.1\msvc2019_64" -L
```

### Visual Studio에서 디버깅

1. Visual Studio에서 프로젝트 열기
2. `F5` 키를 눌러 디버그 모드로 실행
3. 중단점 설정하여 디버깅 가능

### vcpkg 패키지 업데이트

```cmd
cd %VCPKG_ROOT%
git pull
.\bootstrap-vcpkg.bat
.\vcpkg upgrade --no-dry-run
```

## 📦 Qt DLL 파일 배치(배포) 방법 (처음부터 차근차근)

DLL 누락 오류를 해결하고 프로그램을 독립적으로 실행 가능하게 만드는 가장 확실하고 공식적인 방법인 `windeployqt` 사용법을 처음부터 단계별로 안내해 드리겠습니다.

### 1단계: 배포 폴더 준비 및 파일 복사

`windeployqt`를 실행하기 전에, 최종 배포 파일들이 모일 깨끗한 폴더를 만들고 필수 파일들을 옮깁니다.

#### 새 폴더 생성

바탕화면 등 찾기 쉬운 곳에 **FileCryptoGUI_Deployment**와 같은 새 폴더를 만듭니다.

**방법 1: 탐색기에서 생성**
1. 바탕화면 또는 원하는 위치에서 우클릭
2. "새로 만들기" → "폴더" 선택
3. 폴더 이름: `FileCryptoGUI_Deployment`

**방법 2: 명령 프롬프트에서 생성**
```cmd
mkdir C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment
```

#### 실행 파일 복사

Qt Creator가 빌드한 실행 파일 **FileCryptoGUI.exe**를 찾아 1단계에서 만든 새 폴더에 복사합니다.

**실행 파일 위치:**
- 일반적인 경로: `C:\Users\sihwa\source\repos\QT_GUI(v1.4)\build\Release\FileCryptoGUI.exe`
- 또는: `C:\Users\sihwa\source\repos\QT_GUI(v1.4)\build-Desktop_Qt_6_10_1_MinGW_64_bit-Release\FileCryptoGUI.exe`

**복사 방법:**
1. 탐색기에서 `FileCryptoGUI.exe` 파일 찾기
2. 우클릭 → "복사"
3. `FileCryptoGUI_Deployment` 폴더로 이동
4. 우클릭 → "붙여넣기"

또는 명령 프롬프트에서:
```cmd
copy "C:\Users\sihwa\source\repos\QT_GUI(v1.4)\build\Release\FileCryptoGUI.exe" "C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment\"
```

#### OpenSSL DLL 복사

OpenSSL을 동적 링크하셨으므로, 필요한 OpenSSL DLL 파일들을 복사합니다.

**필요한 OpenSSL DLL 파일:**
- `libcrypto-3-x64.dll` (또는 `libcrypto-1_1-x64.dll`)
- `libssl-3-x64.dll` (또는 `libssl-1_1-x64.dll`)

**OpenSSL DLL 위치:**
- vcpkg 사용 시: `C:\Users\sihwa\source\repos\vcpkg\installed\x64-windows\bin\`
- 또는: `C:\Program Files\OpenSSL-Win64\bin\`

**복사 방법:**
```cmd
copy "C:\Users\sihwa\source\repos\vcpkg\installed\x64-windows\bin\libcrypto-3-x64.dll" "C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment\"
copy "C:\Users\sihwa\source\repos\vcpkg\installed\x64-windows\bin\libssl-3-x64.dll" "C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment\"
```

**확인:**
`FileCryptoGUI_Deployment` 폴더에 다음 파일들이 있어야 합니다:
- `FileCryptoGUI.exe`
- `libcrypto-3-x64.dll` (또는 해당 버전)
- `libssl-3-x64.dll` (또는 해당 버전)

### 2단계: Qt 환경 명령 프롬프트 실행 (가장 중요한 부분)

일반 CMD에서는 `windeployqt` 명령을 인식하지 못합니다. Qt 도구가 있는 경로를 환경 변수에 추가해 주는 스크립트를 직접 실행해야 합니다.

#### 일반 CMD 실행

1. Windows 검색창에 `cmd`를 입력
2. "명령 프롬프트" 선택하여 실행

#### Qt 환경 스크립트 경로 확인

Qt 설치 경로에 따라 다릅니다. 일반적인 경로:

**MinGW 사용 시:**
```
C:\Qt\6.10.1\mingw_64\bin\qtvars.bat
```

**Visual Studio 사용 시:**
```
C:\Qt\6.10.1\msvc2019_64\bin\qtvars.bat
```

**실제 경로 확인 방법:**
1. Qt 설치 경로 확인: `C:\Qt\` 폴더 열기
2. 설치된 버전 폴더 확인 (예: `6.10.1`)
3. 컴파일러 폴더 확인 (예: `mingw_64` 또는 `msvc2019_64`)
4. `bin` 폴더 안에 `qtvars.bat` 파일이 있는지 확인

#### 스크립트 실행

CMD 창에 다음 명령을 입력하고 Enter를 누릅니다:

**MinGW 사용 시:**
```cmd
"C:\Qt\6.10.1\mingw_64\bin\qtvars.bat"
```

**Visual Studio 사용 시:**
```cmd
"C:\Qt\6.10.1\msvc2019_64\bin\qtvars.bat"
```

**실행 결과:**
- 스크립트가 실행되면 프롬프트가 `C:\Qt\6.10.1\mingw_64>` 등으로 변경됩니다
- 환경 설정이 완료되어 `windeployqt` 명령을 사용할 수 있습니다

**참고:** `qtvars.bat` 파일이 없다면, Qt 경로를 직접 PATH에 추가할 수도 있습니다:
```cmd
set PATH=%PATH%;C:\Qt\6.10.1\mingw_64\bin
```

### 3단계: windeployqt 실행

환경 설정이 완료된 CMD 창에서 1단계에서 만든 배포 폴더로 이동하여 `windeployqt` 명령을 실행합니다.

#### 배포 폴더로 이동

**방법 1: cd 명령어 사용**
```cmd
cd C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment
```

**방법 2: 드래그 & 드롭 (가장 쉬운 방법)**
1. CMD 창에 `cd ` (띄어쓰기 포함)를 입력
2. 탐색기에서 `FileCryptoGUI_Deployment` 폴더를 찾기
3. 폴더를 CMD 창으로 드래그 & 드롭
4. Enter를 누릅니다

**확인:**
프롬프트가 `C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment>`로 변경되면 성공입니다.

#### DLL 자동 배치 실행

폴더 이동 후, 다음 명령을 입력하고 Enter를 누릅니다:

```cmd
windeployqt FileCryptoGUI.exe
```

**실행 결과:**
- `windeployqt`가 필요한 Qt DLL 파일들을 자동으로 찾아서 복사합니다
- 다음과 같은 메시지들이 출력됩니다:
```
Updating Qt6Core.dll...
Updating Qt6Widgets.dll...
Updating Qt6Gui.dll...
Creating directory platforms...
Updating platforms\qwindows.dll...
...
```

**복사되는 파일들:**
- `Qt6Core.dll`
- `Qt6Widgets.dll`
- `Qt6Gui.dll`
- `platforms\qwindows.dll` (Windows 플랫폼 플러그인)
- 기타 필요한 Qt 플러그인들

**완료 확인:**
메시지 출력이 멈추고 프롬프트가 다시 나타나면 완료입니다.

### 4단계: 최종 테스트

`windeployqt` 실행이 완료되면 배포된 프로그램이 제대로 작동하는지 테스트합니다.

#### CMD 창 닫기

테스트를 위해 CMD 창을 닫아도 됩니다 (또는 그대로 두어도 됩니다).

#### 프로그램 실행 테스트

1. **탐색기에서 실행:**
   - `FileCryptoGUI_Deployment` 폴더로 이동
   - `FileCryptoGUI.exe`를 더블클릭
   - GUI 화면이 정상적으로 나타나면 성공!

2. **다른 위치에서 테스트 (권장):**
   - `FileCryptoGUI_Deployment` 폴더를 다른 위치로 복사 (예: `C:\temp\`)
   - 또는 USB 드라이브에 복사
   - 해당 위치에서 `FileCryptoGUI.exe` 실행
   - 정상 작동하면 배포 성공!

#### 최종 폴더 구조 확인

`FileCryptoGUI_Deployment` 폴더 구조는 다음과 같아야 합니다:

```
FileCryptoGUI_Deployment/
├── FileCryptoGUI.exe          (실행 파일)
├── libcrypto-3-x64.dll        (OpenSSL)
├── libssl-3-x64.dll           (OpenSSL)
├── Qt6Core.dll                (Qt Core)
├── Qt6Widgets.dll             (Qt Widgets)
├── Qt6Gui.dll                 (Qt GUI)
├── platforms/
│   └── qwindows.dll          (Windows 플랫폼 플러그인)
└── (기타 필요한 Qt 플러그인들)
```

### 문제 해결

#### "windeployqt를 찾을 수 없습니다" 오류

**해결 방법:**

1. **Qt 환경 스크립트가 제대로 실행되었는지 확인:**
   - 프롬프트가 `C:\Qt\...`로 변경되었는지 확인
   - 다시 `qtvars.bat` 실행

2. **전체 경로로 실행:**
```cmd
"C:\Qt\6.10.1\mingw_64\bin\windeployqt.exe" FileCryptoGUI.exe
```

3. **PATH에 Qt bin 폴더 추가:**
```cmd
set PATH=%PATH%;C:\Qt\6.10.1\mingw_64\bin
windeployqt FileCryptoGUI.exe
```

#### "DLL을 찾을 수 없습니다" 오류 (실행 시)

**해결 방법:**

1. **누락된 DLL 확인:**
   - 오류 메시지에서 어떤 DLL이 누락되었는지 확인
   - 해당 DLL을 Qt 설치 폴더에서 찾아 복사

2. **windeployqt 재실행:**
```cmd
windeployqt --force FileCryptoGUI.exe
```

3. **OpenSSL DLL 확인:**
   - `libcrypto-3-x64.dll`과 `libssl-3-x64.dll`이 있는지 확인
   - 없으면 vcpkg 폴더에서 복사

#### "플러그인을 로드할 수 없습니다" 오류

**해결 방법:**

1. **platforms 폴더 확인:**
   - `platforms\qwindows.dll` 파일이 있는지 확인
   - 없으면 Qt 설치 폴더에서 수동 복사:
```cmd
copy "C:\Qt\6.10.1\mingw_64\plugins\platforms\qwindows.dll" "platforms\"
```

### 배포 패키징

배포를 위한 최종 ZIP 파일 생성:

**PowerShell 사용:**
```powershell
Compress-Archive -Path "C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment\*" -DestinationPath "C:\Users\sihwa\Desktop\FileCryptoGUI_Release.zip"
```

**7-Zip 사용:**
```cmd
"C:\Program Files\7-Zip\7z.exe" a FileCryptoGUI_Release.zip "C:\Users\sihwa\Desktop\FileCryptoGUI_Deployment\*"
```

이제 ZIP 파일을 다른 컴퓨터에 복사하여 압축 해제 후 실행할 수 있습니다!

