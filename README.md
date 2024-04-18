# shellcooler
a simple shellcode loader in rust

## 实现
通过windows-rs调用Windows API (Memory::VirtualAlloc, Threading::CreateThread)实现shellcode load。

通过对称加密shellcode来显示静态免杀。


## 使用说明

安装rust编译环境，跨平台编译未测试。


## 操作步骤
- 自行生成raw版shellcode （使用msfvenom、cobalt strike或其它）。 CS上，当前版本推荐使用stager载荷，效果相对更好。

- 将生成的shellcode文件在本项目根目录，修改`build.rs`文件中的`RAW_SC`值为shellcode文件路径。

- 执行`cargo build`进行编译。

- 生成的可执行文件在`target/debug`目录下

- 生成无黑窗口的exe: `cargo rustc --bin shellcooler -- -Clink-args="/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup"`

## 进化日志

- v0.1.3
    
    弃用openssl，改用aes-gcm-siv。 同步升级依赖库。

- v0.1.2

    生成无黑窗口的exe: `cargo rustc --bin shellcooler -- -Clink-args="/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup"`
    参考：https://stackoverflow.com/questions/29763647/how-to-make-a-program-that-does-not-display-the-console-window


- v0.1.1

    可生成DLL。  (`cargo build --lib`)

- v0.1.0

    **cobalt strike stageless payload** [Virustotal\(2/70\)](https://www.virustotal.com/gui/file/5ce681c04295e2a65be7504c4b2e7907317d621741761b1f816dccfa0ab9cd67)
    运行时被Windows Defender查杀，云沙盒报毒。

    **cobalt strike stager payload** [Virustotal\(0/69\)](https://www.virustotal.com/gui/file/8d06c44b332f87fb0156e1a2f58a4fa88a02472c714eedb9461fa812a4d8eee8)
    运行时被Windows Defender查杀，云沙盒检测出Cobalt Strike Shellcode。
