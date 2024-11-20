![Hannibal](documentation-payload/hannibal/Hannibal.svg)

This is a mirror of: https://github.com/MythicAgents/Hannibal

Hannibal is a x64 Windows Agent written in fully position independent C (plus a tiny bit of C++). It is based off the [Stardust](https://github.com/Cracked5pider/Stardust) template created by @C5pider.

## Use Case

Hannibal is intended to be used as a Stage 1 agent. It follows these design principles:

- Small -- A full sized .bin of Hannibal is ~45KB.
- Modular -- Can select/remove which commands to compile into agent. Can reduce size to ~25KB.
- Simple -- Focus is on initial foothold abilities vs providing an entire armada of functionality.

Additionally, this project aims to provide education regarding position independent coding, agent design, Mythic agent dev, and C programming for both offensive and defensive resources. 

Included is functionality to build a debug version which is useable in a GUI IDE Debugger such as VSCode for increased accessibility. Hannibal can be compiled on Linux, or Windows. See the [companion article](https://silentwarble.com/posts/making-monsters-1) for further information on how to set up an environment for Hannibal development.

Users are encouraged to leverage this to heavily modify and make your own versions. DM me and let me know what you come up with!

## Installation
To install Hannibal, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory, use the following command to install Hannibal as the **root** user:

```
./mythic-cli install github https://github.com/MythicAgents/Hannibal.git
```

From the Mythic install directory, use the following command to install Hannibal as a **non-root** user:

```
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Hannibal.git
```

## Notable Features
- Small size
- Modular Compilation
- Post-Ex Capability with [HBINs](https://github.com/silentwarble/hbin_template)
- Ekko Sleep
- Replaceable Profile

## Commands Manual Quick Reference

| Command        | Syntax                                                                                                                   | Description                                                                                             |
|----------------|--------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| agentinfo      | `agentinfo`                                                                                                              | Returns internal information about the agent such as memory location, download/upload status etc.       |
| cd             | `cd [path]`                                                                                                              | Changes current working directory for host process.                                                     |
| cp             | `cp [src_path] [dst_path]`                                                                                               | Copy a file or folder to a dst. Copies folders recursively.                                             |
| execute        | `execute [path + args]`                                                                                                  | Executes CreateProcess for the given process string.                                                    |
| execute_hbin   | `execute_hbin <modal_popup>`                                                                                             | Opens a modal so you can upload and execute an hbin. Note args are position and type sensitive.         |
| exit           | `exit or exit thread`                                                                                                    | Exits the agent either killing the process or just the current thread.                                  |
| hostname       | `hostname`                                                                                                               | Return hostname of the machine.                                                                         |
| ipinfo         | `ipinfo`                                                                                                                 | Return information about the active network devices on the machine.                                     |
| listdrives     | `listdrives`                                                                                                             | Return information about the mounted drives and disk space.                                             |
| ls             | `ls [path]`                                                                                                              | Returns a directory listing of the path.                                                                |
| mkdir          | `mkdir [path]`                                                                                                           | Creates a new directory.                                                                                |
| mv             | `mv [src_path] [dst_path]`                                                                                               | Move a file or folder to a dst. Moves folders recursively.                                              |
| ps             | `ps`                                                                                                                     | Return list of running processes on machine.                                                            |
| pwd            | `pwd`                                                                                                                    | Return current working directory of host process.                                                       |
| rm             | `rm [path]`                                                                                                              | Deletes a file or folder. Folders are deleted recursively. (Be careful!)                                |
| sleep          | `sleep [interval] [jitter]`                                                                                              | Sets the sleep/jitter for the agent.                                                                    |
| whoami         | `whoami`                                                                                                                 | Return current user and domain.                                                                         |
| upload         | `upload <modal>`                                                                                                         | Provides a modal to upload a file the agent. Needs full path plus filename. Uploads in chunks.          |
| download       | `download [path]`                                                                                                        | Downloads a file from agent. Downloads in chunks.                                                       |


## Supported C2 Profiles

### [HTTP Profile](https://github.com/MythicC2Profiles/http)

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile. Currently Hannibal only supports POST requests, User Agent, POST URI, sleep, jitter modifications. Toggle key-exchange off as that is not supported.

## Notice

 - This is an initial release agent written in PIC C with zero exception handling. There is a high likelihood there are bugs. Test extensively before using in live Ops.
 - Hannibal needs much more field testing before it is fully Op ready. Have backup channels.
 - Hannibal makes no promises regarding evasion.
 - Hannibal has only been tested with Mythic v3.3.1-rc25.
 - Hannibal has only been tested on Windows 11 23H2.
 - Hannibal has only been executed via the included loader and as a debug exe. Your invocation method will need testing.
 - The Mythic builds only give back shellcode. If you want an exe build with debug_makefile.
 - Hannibal has not been tested in a CFG process, so unknown how Ekko behaves.

## Known-Issues

- Build Times - Build times can be slow (~2min @ 2core 2gb) depending on the hardware you're compiling on. This is due to it being tricky to handle incremental compilation due to adding/removing cmds. See the makefiles for more info. There are ways to get near instant builds so not a deal-killer. Also be aware it will spike resource utilization. Test accordingly. You can watch with top/htop to keep an eye on it.
- OPSEC - There are many TODOs regarding better OPSEC. Plaintext strings in memory, unencrypted structures, calling hooked APIs, etc...For now Hannibal is intended to serve as a starting point for you to customize privately.
- There is no unit testing currently. TODO.


## Contributing

If you'd like to contribute and are looking for something to work on, search the codebase for "TODO:". These items are preferred:

- **Improve Memory Management**
- Reducing Size of Agent
- Reduce Complexity/Code
- Consistency of Design
- Stability
- Performance
- Reduce API Calls
- Improve Network Messaging
- Improve Error Cases
- Basic evasions
- Better OPSEC
- Write HBINs

If adding functionality try to keep things loosely coupled for modularity purposes. Try to follow:

- Prefer snake case when it makes sense
- Descriptive variable names
- Self documenting code
- Comments explain why more than what

## Credits

These projects or snippets of them were either directly implemented or modified in making Hannibal. Cheers and thank you for the code! If I missed any please message me and I'll get them added.

- https://github.com/MythicAgents/Apollo
- https://github.com/MythicAgents/Athena
- https://github.com/Cracked5pider/Stardust
- https://github.com/HavocFramework/Havoc/tree/main/payloads/Demon
- https://github.com/Cracked5pider/Ekko
- https://github.com/kokke/tiny-AES-c
- https://github.com/robertdavidgraham/whats-dec/
- https://github.com/zhicheng/base64
