# Kernel64Patcher
A 64 Bit kernel patcher based on xerub's patchfinder64

## Linux Compiling
```
sudo apt update && sudo apt install -y uuid-dev libz-dev git curl
git clone --recursive https://github.com/charlesnathansmith/maloader-no-sysctl
cd maloader-no-sysctl
make release
cd ..
gcc Kernel64Patcher.c -o Kernel64Patcher -I./maloader-no-sysctl/include/ -L./maloader-no-sysctl/
```
## Mac Compiling 
```
gcc Kernel64Patcher.c -o Kernel64Patcher
```
## Usage:
```
./Kernel64Patcher kcache.raw kcache.patched -a
```
## Credits/Thanks
* xerub for patchfinder64
* iH8sn0w for code
