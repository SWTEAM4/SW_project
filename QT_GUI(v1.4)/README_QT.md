# Qt GUI 빌드 가이드

## 요구사항

- CMake 3.16 이상
- Qt 6.x
- C/C++ 컴파일러 (MSVC, GCC, Clang)

## Windows에서 빌드

1. Qt 설치 (Qt 6.x)
2. CMake 설치
3. 빌드:

```bash
mkdir build
cd build
cmake .. -DCMAKE_PREFIX_PATH="C:/Qt/6.x.x/msvc2019_64"
cmake --build . --config Release
```

실행 파일은 `build/Release/FileCryptoGUI.exe`에 생성됩니다.

## macOS에서 빌드

1. Qt 설치:
```bash
brew install qt@6
```

2. 빌드:
```bash
mkdir build
cd build
cmake .. -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/qt@6"
cmake --build . --config Release
```

실행 파일은 `build/FileCryptoGUI.app`에 생성됩니다.

## Linux에서 빌드

1. Qt 설치:
```bash
sudo apt-get install qt6-base-dev qt6-base-dev-tools
```

2. 빌드:
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## 사용 방법

1. 프로그램 실행
2. "Select File" 버튼으로 암호화/복호화할 파일 선택
3. 패스워드 입력 (영문+숫자, 대소문자 구분, 최대 10자)
4. 암호화: AES 키 길이 선택 후 "Encrypt" 버튼 클릭
5. 복호화: "Decrypt" 버튼 클릭

## 주의사항

- 암호화 시 선택한 AES 키 길이를 기억하세요 (자동으로 파일에 저장됨)
- 복호화 시 암호화에 사용한 패스워드를 정확히 입력해야 합니다
- 파일이 손상되었거나 패스워드가 틀리면 복호화가 실패합니다

