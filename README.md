# shellcoolerer
a simple shellcode loader in rust

## 实现
通过windows-rs调用Windows API (Memory::VirtualAlloc, Threading::CreateThread)实现shellcode load。

通过aes-256-cbc加密shellcode来显示静态免杀，目前采用的openssl，有点臃肿低效麻烦。


## 使用说明
- 需要在Windows上使用。

- 安装rust、openssl、perl(不是很确定)，注意配置PATH和OPENSSL_DIR环境变量。


## 操作步骤
- 自行生成raw版shellcode （使用msfvenom、cobalt strike或其它）。 CS上，当前版本推荐使用stager载荷，效果相对更好。

- 将生成的shellcode文件在本项目根目录，修改`build.rs`文件中的`RAW_SC`值为shellcode文件路径。

- 执行`cargo build --release`进行编译。

- 生成的可执行文件在`target/release`目录下


## 进化日志

- v0.1.0

    **cobalt strike stageless payload** [Virustotal\(2/70\)](https://www.virustotal.com/gui/file/5ce681c04295e2a65be7504c4b2e7907317d621741761b1f816dccfa0ab9cd67)
    运行时被Windows Defender查杀，云沙盒报毒。

    **cobalt strike stager payload** [Virustotal\(0/69\)](https://www.virustotal.com/gui/file/8d06c44b332f87fb0156e1a2f58a4fa88a02472c714eedb9461fa812a4d8eee8)
    运行时被Windows Defender查杀，云沙盒检测出Cobalt Strike Shellcode。
