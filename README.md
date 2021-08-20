# PEB-PPIDspoofing_Csharp



Blog link: working on it

* Create a process with a fake PPID and a fake command line.
* It a test version, only tested in Win10_x64.
* The purpose is to bypass Sysmon and parent process detection
* You are gonna need to change the PPID in the Main function, OR we could add a function(like a funciton call Find_explorer) to find a process's PID as a parent process. (Most of the time, we would choose explorer.exe). 
* ~~I am gonna update the Find_explorer function and fix some bugs soon~~(DONE).
* **Importance**!   **The Fake command line must be longer than the real one, but also there are some ideas to fix that(I am gonna talk about that in my blog), for now, you just need to remember The fake command line must be longer than the real one**
* It only works with x64, cause the offset different from x86, also maybe I am gonna update that too.
* **I updated the code, now it's gonna find "explorer" pid automaticlly, but also you could change explorer to other process name.**
* Feel free to make any issues and advises



## Usage

1. Select a process pid as parent process pid.

   ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/Screen%20Shot%202021-05-31%20at%208.39.24%20PM.png)

   

2. Set the fake command line and the real command line.

   ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/PEB-PPIDspoofing_Csharp_fakeCommandline.png)

   ![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/PEB-PPIDspoofing_Csharp_RealCommandline.png)

   

3. Launch the assembly through a white list application.

   
## To-Do list
1. Restruct PEB-PPIDspoofing_Csharp code.


## Reference link 

1. https://medium.com/@r3n_hat/parent-pid-spoofing-b0b17317168e
2. https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office/bypassing-malicious-macro-detections-by-defeating-child-parent-process-relationships
3. https://www.pinvoke.net
4. https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/
5. https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/
6. https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
7. https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line/
8. https://gist.github.com/xpn/1c51c2bfe19d33c169fe0431770f3020#file-argument_spoofing-cpp
9. https://github.com/christophetd/spoofing-office-macro
10. https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing



