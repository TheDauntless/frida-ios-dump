# frida-ios-dump
Pull a decrypted IPA from a jailbroken device

Supports 2.x and 3.x

## Usage

1. Install `Frida` package on a jailbroken device via a package manager. See [documentation](https://frida.re/docs/ios/).
2. Set up SSH forwarding over USB (Default 2222 -> 22)
    1. Install `usbmuxd`, `iproxy`
    2. Run `usbmuxd` as a systemd service (`sudo systemctl start usbmuxd`) or from a terminal (`sudo usbmuxd -f -p`)
    3. `iproxy 2222 22`
4. Run `frida-ps -Us` to list existing apps and find your app.
5. Run `./dump.py <Display name or Bundle identifier>`

For SSH/SCP make sure you have your public key added to the target device's `~/.ssh/authorized_keys` file or use username/password

Alternatively, connect directly over SSH:
```
python3 dump.py -H <ip> -p 22 -u mobile -P 'alpine' <bundleid>
```

```sh
$ ./dump.py Aftenposten
Start the target app Aftenposten
Dumping Aftenposten to /var/folders/wn/9v1hs8ds6nv_xj7g95zxyl140000gn/T
start dump /var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/AftenpostenApp
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/AFNetworking.framework/AFNetworking
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/ATInternet_iOS_ObjC_SDK.framework/ATInternet_iOS_ObjC_SDK
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/SPTEventCollector.framework/SPTEventCollector
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/SPiDSDK.framework/SPiDSDK
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCore.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreData.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreGraphics.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreImage.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreLocation.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftDarwin.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftDispatch.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftFoundation.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftObjectiveC.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftQuartzCore.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftUIKit.dylib
Generating Aftenposten.ipa

Done.
```

Congratulations!!! You've got a decrypted IPA file.

Drag to [MonkeyDev](https://github.com/AloneMonkey/MonkeyDev), Happy hacking!

## Troubleshooting

### "Timeout was reached"

Check if the app is in execution and close it.

### "unexpected error while resuming process: (os/kern) failure"

Open the application before dumping.

### `dump.py` causes device to rebbot, lost connection, or unexpected error while probing dyld of target process

Open the application before dumping.
