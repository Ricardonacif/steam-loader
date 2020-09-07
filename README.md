# SteamLoader - Bypassing Steam ThreadHideFromDebugger

A simple bypass for Steam's `ThreadHideFromDebugger` anti-debugging technique that doesn't allow the execution flow to be transfered to the debugger when a breakpoint hits. This technique is present in (old?) Steam games like Orcs Must Die 2, F.E.A.R. 3, DeusEx, Brinck, Fall out series, Duke Nukem. As soon as the breakpoint is hit, the game exits. I [wrote a full explanation on ](http://google.com) of it on [Guided Hacking forum](https://google.com/). The Visual Studio solution contains two projects:

### SteamDll
It's a DLL that gets injected into Steam and later into game loaders and the game itself. It hooks `CreateProcess` (A and W) API calls to inject itself on the new processes in order to disable the `ThreadHideFromDebugger` flag. It has to be done early in the process life cycle, so it ensures the process main thread is created in a `SUSPENDEND` state while it do its thing. 
### SteamInjector
Well, it's the loader. It simply finds the Steam process and inject the DLL above.

### TODO

1. It could be used to receive a DLL file path and act as a injector directly from Steam. Its manual mapping injection technique was based of this [awesome tutorial from Broihon](https://www.youtube.com/watch?v=qzZTXcBu3cE).
1.  Change the Steam's UI so you could enable/disable it. And also select a DLL to be injected maybe?