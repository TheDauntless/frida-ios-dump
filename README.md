# frida-ios-dump

Pull a decrypted IPA from a jailbroken device

## Features

* Fuzzy matching on Bundle ID or App Name
* Possibility to pause app after launch
* Creates entire IPA file
* No reliance on ObjC API

## Requirements

* Frida 17.x+

## Usage

1. Install `Frida` package on a jailbroken device via a package manager. See [documentation](https://frida.re/docs/ios/).
2. (optional) Set up SSH forwarding over USB (Default 2222 -> 22). If not, specify SSH configuration when running `dump.py`
    1. Install `usbmuxd`, `iproxy`
    2. Run `usbmuxd` as a systemd service (`sudo systemctl start usbmuxd`) or from a terminal (`sudo usbmuxd -f -p`)
    3. `iproxy 2222 22`
4. Run `./dumpy.py -l` to view all apps
5. Run `./dump.py <query>`
   1. Run `./dump.py -w <query>` to have the application pause at startup

## CLI

The script defaults to a connection on root@localhost:2222 but can be configured using `-H`, `-p`, `-u` and `-P`

```code
python3 dump.py -h
usage: dump.py [-h] [-l] [-o OUTPUT_IPA] [-H SSH_HOST] [-p SSH_PORT] [-u SSH_USER] [-P SSH_PASSWORD] [-K SSH_KEY_FILENAME] [-w] [-v] [target]

frida-ios-dump v3.0 - Decrypt iOS applications on non-jailbroken devices using Frida

positional arguments:
  target                Bundle identifier or display name of the target app

options:
  -h, --help            show this help message and exit
  -l, --list            List the installed apps
  -o, --output OUTPUT_IPA
                        Specify name of the decrypted IPA
  -H, --host SSH_HOST   Specify SSH hostname
  -p, --port SSH_PORT   Specify SSH port
  -u, --user SSH_USER   Specify SSH username
  -P, --password SSH_PASSWORD
                        Specify SSH password
  -K, --key_filename SSH_KEY_FILENAME
                        Specify SSH private key file path
  -w, --wait            Pause app after launch
  -v, --verbose         Enable verbose output
```

Connecting over different SSH configuration:

```code
python3 dump.py -H <ip> -p 22 -u mobile -P 'alpine' <bundleid>
```

For SSH/SCP make sure you have your public key added to the target device's `~/.ssh/authorized_keys` file or use username/password

## Development

```bash
pip3 install -r requirements.txt
npm install --save-dev @types/frida-gum
frida-pm install frida-fs
npm run build
./dump.py <bundleid>
```

## Example usage

```sh
./dump.py -w sto
Multiple matching applications found:
  [0] Sileo (org.coolstar.SileoStore)
  [1] Stocks (com.apple.stocks)
  [2] TrollStore (com.opa334.TrollStore)
  [3] iTunes Store (com.apple.MobileStore)
  [4] App Store (com.apple.AppStore)
Select an application by index: 1
Target application: Stocks (com.apple.stocks)
Already running, attaching...
0.00B [00:00, ?B/s]
Generating "Stocks.ipa"
Done, resuming application
```

## Troubleshooting

### App crashes before dump can be made

Use `-w` argument to pause the application when launching.

### "Timeout was reached"

Close the application. Sometimes an application is running even if it's not listed in the app switcher. In that case, use `kill <pid>` via SSH.

## Credits

Original author / repo: [https://github.com/AloneMonkey/frida-ios-dump](AloneMonkey/frida-ios-dump)