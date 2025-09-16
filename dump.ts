import * as Fs from "frida-fs";
import * as Path from "path";


var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.writeUtf8String(str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readByteArray(l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readU8();
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.writeU8(n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readU16();
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.writeU16(n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readU32();
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.writeU32(n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readU64();
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.writeU64(n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return addr.readPointer();
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return addr.writePointer(n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.getGlobalExportByName(name);
    if (nptr === null) {
        error("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                error("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = nptr.readPointer();
            if (typeof datalet === "undefined") {
                error("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var remove = getExportFunction("f", "remove", "int", ["pointer"]);
var access = getExportFunction("f", "access", "int", ["pointer", "int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

function getDocumentDir() {
    return Path.join(Process.getHomeDir(), "Documents")
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModules();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n-str.length+1).join("0")+str;
}

function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        error("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + newmodname + ".decrypted";
    var oldmodpath = modules[i].path;


    if(!access(allocStr(newmodpath),0)){
        remove(allocStr(newmodpath));
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0o600);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 ) {
        error("Cannot open target file: " + newmodpath);
        return;
    }
    if(foldmodule == -1){
        error("Cannot open original file: " + oldmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if(magic == FAT_CIGAM || magic == FAT_MAGIC){
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if(fileoffset == 0 || filesize == 0)
            return;

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for(var i = 0; i < (filesize / BUFSIZE); i++) { //parseInt
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    }else{
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while(readLen = read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
    }

    close(fmodule);
    close(foldmodule);
    return newmodpath
}

function ensureLoaded(moduleName, path) {
    const module = Process.findModuleByName(moduleName)
    if (module) {
        verbose("[frida-ios-dump]: " + moduleName + " is loaded. ");
        return
    } else {
        Module.load(path)
        if (Process.findModuleByName(moduleName)) {
            warn("[frida-ios-dump]: " + moduleName + " has been loaded forcefully.");
        } else {
            warn("[frida-ios-dump]: " + moduleName + " has not been loaded.");
        }
    }
}


function loadAllDynamicLibrary(app_path) {

    let entries: Fs.DirectoryEntry[] = Fs.list(app_path)

    for (const entry of entries) {

        var file_name = entry.name
        if (entry.name === "." || entry.name === "..") continue;

        var file_path = Path.join(app_path, entry.name)
        if (file_name.endsWith(".dylib") || entry.name.endsWith(".framework/")) {
            ensureLoaded(entry.name, file_path)
            file_name
        }
        else if (entry.type == Fs.constants.DT_DIR) {
            loadAllDynamicLibrary(file_path);
        }
    }
}
function log(msg) {
    send({ "log": msg});
}
function error(msg) {
    send({"error": msg});
}
function warn(msg) {
    send({"warn": msg});
}
function verbose(msg) {
    send({ "verbose": msg});
}

(globalThis as any).dumpIPA = dumpIPA;

function dumpCommand(message) {

    dumpIPA()
}

function dumpIPA(){
    modules = getAllAppModules();

    const mainModule = Process.mainModule;
    if (!mainModule) {
        error("[-] Could not find Process.mainModule");
        return;
    }

    // Source: App bundle directory
    const bundleBinaryPath = mainModule.path;
    const appDir = Path.dirname(bundleBinaryPath);
    verbose("App bundle directory: " + appDir);


    loadAllDynamicLibrary(appDir);

    // start dump
    modules = getAllAppModules();

    log("Dumping binaries")
    for (var i = 0; i  < modules.length; i++) {
        verbose("\t" + modules[i].path.substring(appDir.length));
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path});
    }
    send({app: appDir.toString()});
    send({done: "ok"});
    // recv(handleMessage);
}

recv('dump', dumpCommand);