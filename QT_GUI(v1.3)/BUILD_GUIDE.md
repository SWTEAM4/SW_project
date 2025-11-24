# Qt GUI 빌드 가이드

이 가이드는 Windows와 macOS에서 Qt GUI 애플리케이션을 빌드하는 방법을 설명합니다.

## 📋 사전 준비사항

### 1. Qt 설치

#### Windows:
1. [Qt 공식 웹사이트](https://www.qt.io/download)에서 Qt 설치 프로그램 다운로드
2. Qt 6.x 버전 선택 (예: Qt 6.5.0)
3. 컴파일러 선택:
   - **Visual Studio 사용 시**: MSVC 2019 64-bit 또는 MSVC 2022 64-bit
   - **MinGW 사용 시**: MinGW 11.2.0 64-bit
4. 설치 경로 확인 (예: `C:\Qt\6.5.0\msvc2019_64`)

#### macOS:
```bash
# Homebrew를 사용한 설치 (권장)
brew install qt@6

# 또는 Qt 공식 설치 프로그램 사용
# https://www.qt.io/download
```

### 2. CMake 설치

#### Windows:
- [CMake 공식 웹사이트](https://cmake.org/download/)에서 설치 프로그램 다운로드
- 설치 시 "Add CMake to system PATH" 옵션 선택

#### macOS:
```bash
brew install cmake
```

### 3. 컴파일러 확인

#### Windows:
- **Visual Studio**: Visual Studio 2019 또는 2022 설치
- **MinGW**: Qt 설치 시 함께 설치되거나 별도 설치

#### macOS:
- Xcode Command Line Tools 설치:
```bash
xcode-select --install
```

## 🔨 빌드 방법

### Windows (Visual Studio 사용)

#### 방법 1: 명령 프롬프트 (CMD) 또는 PowerShell

1. **프로젝트 폴더로 이동:**
```cmd
cd C:\Users\sihwa\source\repos\SWTEAM4\SW_project\project_sw
```

2. **빌드 폴더 생성:**
```cmd
mkdir build
cd build
```

3. **Qt 경로 확인:**
   - Qt가 `C:\Qt\6.5.0\msvc2019_64`에 설치되어 있다고 가정
   - 실제 경로에 맞게 수정하세요

4. **CMake 실행:**
```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.5.0\msvc2019_64"
```

5. **빌드:**
```cmd
cmake --build . --config Release
```

6. **실행 파일 위치:**
   - `build\Release\FileCryptoGUI.exe`

#### 방법 2: Visual Studio에서 직접 열기

1. CMake GUI 실행
2. "Browse Source"에서 프로젝트 폴더 선택
3. "Browse Build"에서 `build` 폴더 선택
4. "Configure" 클릭
5. "CMAKE_PREFIX_PATH"에 Qt 경로 입력 (예: `C:\Qt\6.5.0\msvc2019_64`)
6. "Generate" 클릭
7. "Open Project" 클릭하여 Visual Studio에서 열기
8. Visual Studio에서 빌드 (F7 또는 Build 메뉴)

### macOS

#### 터미널에서 빌드:

1. **프로젝트 폴더로 이동:**
```bash
cd ~/source/repos/SWTEAM4/SW_project/project_sw
```

2. **빌드 폴더 생성:**
```bash
mkdir build
cd build
```

3. **Qt 경로 확인:**
```bash
# Homebrew로 설치한 경우
brew --prefix qt@6
# 일반적으로 /opt/homebrew/opt/qt@6 또는 /usr/local/opt/qt@6
```

4. **CMake 실행:**
```bash
cmake .. -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/qt@6"
```

5. **빌드:**
```bash
cmake --build . --config Release
```

6. **실행 파일 위치:**
   - `build/FileCryptoGUI.app`
   - 실행: `open build/FileCryptoGUI.app`

## 🐛 문제 해결

### Windows: "Qt6 not found" 오류

**해결 방법:**
1. Qt 설치 경로 확인:
```cmd
dir C:\Qt
```

2. 정확한 경로로 다시 시도:
```cmd
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.5.0\msvc2019_64"
```

3. 또는 환경 변수 설정:
```cmd
set CMAKE_PREFIX_PATH=C:\Qt\6.5.0\msvc2019_64
cmake ..
```

### macOS: "Qt6 not found" 오류

**해결 방법:**
1. Qt 설치 확인:
```bash
brew list qt@6
```

2. 경로 확인:
```bash
brew --prefix qt@6
```

3. 올바른 경로로 다시 시도:
```bash
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
```

### "CMake not found" 오류

**해결 방법:**
- CMake가 PATH에 있는지 확인:
```bash
# Windows
cmake --version

# macOS
which cmake
```

- 없으면 PATH에 추가하거나 전체 경로로 실행

### 컴파일 오류: "undefined reference"

**해결 방법:**
- `cli.c`의 `main` 함수가 컴파일되지 않도록 `BUILD_GUI`가 정의되어 있는지 확인
- CMakeLists.txt에 `BUILD_GUI` 정의가 포함되어 있는지 확인

## 📝 빠른 참조

### Windows (PowerShell):
```powershell
cd C:\Users\sihwa\source\repos\SWTEAM4\SW_project\project_sw
mkdir build -ErrorAction SilentlyContinue
cd build
cmake .. -DCMAKE_PREFIX_PATH="C:\Qt\6.5.0\msvc2019_64"
cmake --build . --config Release
.\Release\FileCryptoGUI.exe
```

### macOS:
```bash
cd ~/source/repos/SWTEAM4/SW_project/project_sw
mkdir -p build && cd build
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
cmake --build . --config Release
open FileCryptoGUI.app
```

## ✅ 빌드 성공 확인

빌드가 성공하면:
- **Windows**: `build\Release\FileCryptoGUI.exe` 파일이 생성됨
- **macOS**: `build\FileCryptoGUI.app` 번들이 생성됨

실행 파일을 더블클릭하거나 명령줄에서 실행하면 GUI 프로그램이 시작됩니다.

