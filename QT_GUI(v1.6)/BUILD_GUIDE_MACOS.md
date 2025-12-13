# macOS 빌드 가이드

이 가이드는 macOS에서 Qt GUI 애플리케이션을 빌드하는 방법을 상세히 설명합니다.

## 📋 사전 준비사항

### 1. Homebrew 설치

Homebrew가 설치되어 있지 않다면 먼저 설치하세요:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Apple Silicon (M1/M2) Mac의 경우:**
- 설치 후 다음 명령어 실행 필요:
```bash
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### 2. 필수 패키지 설치

#### Qt 6 설치

**방법 1: Homebrew로 설치 (권장)**
```bash
brew install qt@6
```

**방법 2: Qt 공식 설치 프로그램**
1. [Qt 공식 웹사이트](https://www.qt.io/download)에서 다운로드
2. 설치 프로그램 실행
3. Qt 6.x 버전 선택
4. 설치 경로 확인 (예: `/Users/username/Qt/6.5.0/macos`)

#### OpenSSL 설치

```bash
brew install openssl
```

**설치 경로:**
- Apple Silicon (M1/M2): `/opt/homebrew/opt/openssl`
- Intel Mac: `/usr/local/opt/openssl`

#### CMake 설치

```bash
brew install cmake
```

#### Xcode Command Line Tools 설치

```bash
xcode-select --install
```

### 3. 설치 확인

다음 명령어로 설치가 제대로 되었는지 확인하세요:

```bash
# Qt 확인
brew list qt@6
brew --prefix qt@6

# OpenSSL 확인
brew list openssl
brew --prefix openssl

# CMake 확인
cmake --version

# 컴파일러 확인
gcc --version
```

## 🔨 빌드 방법

### 방법 1: 터미널에서 빌드

#### 1단계: 프로젝트 폴더로 이동

```bash
cd ~/source/repos/QT_GUI\(v1.4\)
```

또는 실제 프로젝트 경로로 이동:
```bash
cd /path/to/QT_GUI\(v1.4\)
```

#### 2단계: 빌드 폴더 생성

```bash
mkdir -p build
cd build
```

#### 3단계: Qt 경로 확인

**Homebrew Qt 사용 시:**
```bash
brew --prefix qt@6
# 출력 예시: /opt/homebrew/opt/qt@6 (Apple Silicon)
# 또는: /usr/local/opt/qt@6 (Intel Mac)
```

**Qt 공식 설치 프로그램 사용 시:**
```bash
# Qt 설치 경로 확인 (예: /Users/username/Qt/6.5.0/macos)
```

#### 4단계: CMake 실행

**Homebrew Qt 사용 시:**
```bash
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
```

**Qt 공식 설치 프로그램 사용 시:**
```bash
cmake .. -DCMAKE_PREFIX_PATH="/Users/username/Qt/6.5.0/macos"
```

#### 5단계: 빌드

```bash
cmake --build . --config Release
```

또는:
```bash
make -j$(sysctl -n hw.ncpu)
```

#### 6단계: 실행

```bash
open FileCryptoGUI.app
```

또는:
```bash
./FileCryptoGUI.app/Contents/MacOS/FileCryptoGUI
```

### 방법 2: Qt Creator에서 빌드

#### 1단계: Qt Creator 설치

**Homebrew로 설치:**
```bash
brew install --cask qt-creator
```

**또는 Qt 공식 설치 프로그램에 포함됨**

#### 2단계: 프로젝트 열기

1. Qt Creator 실행
2. "Open Project" 또는 "File → Open File or Project"
3. `CMakeLists.txt` 파일 선택

#### 3단계: 빌드 설정

1. 왼쪽 "프로젝트" 탭 클릭
2. "Build" 섹션에서 "Build Environment" 확장
3. 환경 변수 추가:

**Homebrew Qt 사용 시:**
- 변수 이름: `CMAKE_PREFIX_PATH`
- 변수 값: `$(brew --prefix qt@6)`

또는 직접 경로 입력:
- Apple Silicon: `/opt/homebrew/opt/qt@6`
- Intel Mac: `/usr/local/opt/qt@6`

**Qt 공식 설치 프로그램 사용 시:**
- 변수 이름: `CMAKE_PREFIX_PATH`
- 변수 값: `/Users/username/Qt/6.5.0/macos`

#### 4단계: 빌드 및 실행

1. 하단 "Build" 버튼 클릭 또는 `Cmd+B`
2. 빌드 완료 후 "Run" 버튼 클릭 또는 `Cmd+R`

## 🐛 문제 해결

### "Qt6 not found" 오류

**해결 방법:**

1. **Qt 설치 확인:**
```bash
brew list qt@6
```

2. **Qt 경로 확인:**
```bash
brew --prefix qt@6
```

3. **CMake 캐시 삭제 후 재시도:**
```bash
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
```

4. **환경 변수로 설정:**
```bash
export CMAKE_PREFIX_PATH=$(brew --prefix qt@6)
cmake ..
```

### "OpenSSL not found" 오류

**해결 방법:**

1. **OpenSSL 설치 확인:**
```bash
brew list openssl
brew --prefix openssl
```

2. **OpenSSL 경로 확인:**
```bash
# Apple Silicon
ls -la /opt/homebrew/opt/openssl

# Intel Mac
ls -la /usr/local/opt/openssl
```

3. **CMakeLists.txt가 자동으로 찾도록 설정되어 있음**
   - Apple Silicon: `/opt/homebrew/opt/openssl`
   - Intel Mac: `/usr/local/opt/openssl`

### "CMake not found" 오류

**해결 방법:**

```bash
# CMake 설치 확인
which cmake
cmake --version

# 없으면 설치
brew install cmake
```

### "Command Line Tools not found" 오류

**해결 방법:**

```bash
xcode-select --install
```

### 빌드 중 링크 오류

**해결 방법:**

1. **OpenSSL 라이브러리 경로 확인:**
```bash
# Apple Silicon
ls -la /opt/homebrew/lib/libssl.dylib
ls -la /opt/homebrew/lib/libcrypto.dylib

# Intel Mac
ls -la /usr/local/lib/libssl.dylib
ls -la /usr/local/lib/libcrypto.dylib
```

2. **빌드 폴더 완전히 삭제 후 재빌드:**
```bash
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
cmake --build . --config Release
```

### "Permission denied" 오류

**해결 방법:**

```bash
# 실행 권한 부여
chmod +x FileCryptoGUI.app/Contents/MacOS/FileCryptoGUI
```

## 📝 빠른 참조

### 전체 빌드 명령어 (한 번에)

**Homebrew Qt 사용 시:**
```bash
cd ~/source/repos/QT_GUI\(v1.4\)
mkdir -p build && cd build
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)"
cmake --build . --config Release
open FileCryptoGUI.app
```

**Qt 공식 설치 프로그램 사용 시:**
```bash
cd ~/source/repos/QT_GUI\(v1.4\)
mkdir -p build && cd build
cmake .. -DCMAKE_PREFIX_PATH="/Users/username/Qt/6.5.0/macos"
cmake --build . --config Release
open FileCryptoGUI.app
```

## ✅ 빌드 성공 확인

빌드가 성공하면:
- `build/FileCryptoGUI.app` 번들이 생성됩니다
- 실행: `open build/FileCryptoGUI.app` 또는 더블클릭

## 🔍 빌드 출력 위치

- **실행 파일**: `build/FileCryptoGUI.app`
- **실제 바이너리**: `build/FileCryptoGUI.app/Contents/MacOS/FileCryptoGUI`
- **리소스 파일**: `build/FileCryptoGUI.app/Contents/Resources/`

## 📌 중요 참고사항

1. **Apple Silicon vs Intel Mac:**
   - Apple Silicon (M1/M2): `/opt/homebrew/`
   - Intel Mac: `/usr/local/`
   - CMakeLists.txt가 자동으로 감지합니다

2. **환경 변수:**
   - 터미널 세션마다 설정하려면 `~/.zshrc` 또는 `~/.bash_profile`에 추가:
   ```bash
   export CMAKE_PREFIX_PATH=$(brew --prefix qt@6)
   ```

3. **Qt Creator 설정:**
   - 프로젝트별 빌드 환경에서 `CMAKE_PREFIX_PATH` 설정 필요
   - 또는 전역 환경 변수로 설정 가능

4. **OpenSSL:**
   - CMakeLists.txt가 Homebrew OpenSSL을 자동으로 찾습니다
   - 별도 설정 불필요

## 🚀 추가 팁

### 디버그 빌드

```bash
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)" -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
```

### 병렬 빌드 (빠른 빌드)

```bash
cmake --build . --config Release -j$(sysctl -n hw.ncpu)
```

### 빌드 정보 확인

```bash
cmake .. -DCMAKE_PREFIX_PATH="$(brew --prefix qt@6)" -L
```

