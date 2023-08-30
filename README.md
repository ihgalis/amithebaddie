# amithebaddie
Some tools to simulate the behavior of malicious software without destroying anything.

# How to start?
## Install .NET SDK
- Visit https://dotnet.microsoft.com/download/dotnet and download it

## Verify
```
dotnet --version
```

## Create a project
```
dotnet new console -n amithebaddie
```

## Download this repo
```
git clone https://github.com/ihgalis/amithebaddie.git
```

## Compile for Windows
```
dotnet publish -c Release -r win-x64 --self-contained true
```

## Find the exe and run by moving the entire dir to Windows
```
bin/Release/net<YOUR_DOT_NET_VERSION>/win-x64/publish
```
