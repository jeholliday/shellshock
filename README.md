# Introduction
In 2014, security researchers found a series of injection vulnerabilities in Bash that came to be known as Shellshock. Several of the vulnerabilities had been in Bash for 25 years before they were patched. The widespread use of Bash caused many different services to be affected and left millions of Unix computers vulnerable. The injection vulnerability could allow remote attackers to send malicious payloads to 

The Bourne-Again Shell (Bash) has become a very commonly used computer program across many different Unix-based operating systems. Versions of Bash exist for Linux, BSD, and macOS. All of these versions share most of their code-base and resulted in the same vulnerability affecting many different operating systems. As a shell, Bash is used to execute commands on a computer. Bash can be used either interactively by a user to type in commands or non-interactively by other computer programs. The commonality of Bash has resulted in many other services relying on Bash 

Injection vulnerabilities allow an attacker to create malicious inputs that alter the expected behavior of a system. Every computer system or program works by accepting inputs, processing the input, and then taking an action. Developers must be careful when making assumptions about the content, form, or source of an input because attackers can maniuplate all of these 

-something  else
- Summary and overview of paper

# Breaking down the Vulnerabilities
Shellshock consists of several different vulnerabilities that relate to how Bash handles environment variables. These variables allow a user or script to define a value once and then reuse that value again by giving it's name. An environment variable definition in Bash might look like `GREETING="Hello, World!"`. After defining this variable, the value `Hello, World!` can be used again by just typing `$GREETING`. Other programs will very frequently pass information to Bash through these environment variables to 

In Bash, it is valid syntax to store Bash commands in an environment variable and then execute them later.

Demonstrating Shellshock requires a vulnerable version of Bash. For my testing, I used Ubuntu 12.04.5 Precise Pangolin. The installer image for this release was created just before Shellshock was published and contains a vulnerable version of Bash 4.2. However, it can be difficult to determine whether or not a specific version number of Bash is vulnerable because the severity of this bug has resulted in every common version receiving patches. Instead, it can be tested for by running an example command and observing the behavior.

## CVE-2014-6271
```
$ env X='() { :; }; echo "CVE-2014-6271 Vulnerable"' bash -c :
```
This vulnerability is the original and most well-known Shellshock vulnerability. If a system is vulnerable, it will print `CVE-2014-6271 Vulnerable`. Otherwise, the version of Bash has been patched. 

```
[1]                                                  [2]
[env X='() { :; }; echo "CVE-2014-6271 Vulnerable"'] [bash -c :]
```
This command consists of two sub-commands that setup the environment and then test it. [1] creates a new environment 
# Exploiting SSH
Secure Shell (SSH) is a service that allows user to securely access a shell on a remote computer. SSH is commonly used because it is extremely useful to be able to execute commands on a remote computer as if you were sitting in front of it. However, the power and ease of use of SSH can create security vulnerabilities if it is improperly secured. By default, SSH will use password authentication to allow users to login with the same password as their account password. For additionally security, a user can instead use a public/private key pair to authenticate with the server. To enable key-based authentication, a user would add their public key to `~/.ssh/authorized_keys`. Then the user could securely log into the computer with their private key.

SSH can be used for both full and restricted shell access. Developers frequently use SSH to manage remote and virtual machines because it allows complete control of the system remotely. In this use case, a developer wants to be able to execute arbitrary commands and have a full shell. However, SSH can also be used by programs to access other machines or automate tasks. It is a good security practice to only give a services the minimum required permissions. Instead of allowing a service to execute arbitrary commands over SSH, a "Forced Command" can be used to restrict a user to only executing one command. When a Forced Command is specified, this user should not be able to execute any other commands.

To enable a forced command using the `authorized_keys` file, it should follow this pattern.
```
command="<command>" <public key> <comment>
```
Example:
```
command="echo goodbye" ssh-rsa AAAAB3Nza...IhoZ+pvQKj ubuntu@precise 
```

SSH can be exploited using Shellshock to breakout of a Forced Command and achieve arbitrary remote code execution. This exploit will only work if the remote user's shell is Bash. In order to use Shellshock, an attacker just needs to find a way to set an environment variable on the remote machine. A malicious environment variable will then be expanded and executed before the Forced Command is executed. Two potential ways to set an environment variable are through the `LC_*` or `SSH_ORIGINAL_COMMAND`.

## LC_*
By default, the config file `/etc/ssh/sshd_config` will include the line `AcceptEnV LANG LC_*`. This line tells the SSH daemon to automatically copy these environment variables from the user's shell to the remote shell. All an attacker needs to do is set one of these variables to a Shellshock payload before SSHing and it will be copied to the remote shell.
```
env LC_PAYLOAD='() { :; }; echo "pwned"' ssh <user>@<server address>
```

## SSH_ORIGINAL_COMMAND
Normally a user can execute a single command over SSH by appending it to the SSH command. When using a Forced Command, the appended command is ignored, but it is stored in the SSH_ORIGINAL_COMMAND environment variable. This feature can then be exploited by including the Shellshock payload in the original command.
```
ssh <user>@<server address> '() { :; }; echo "pwned"'
```

# Exploiting DHCP
The Dynamic Host Configuration Protocol (DHCP) defines a method for dynamically allocating IP addresses to clients in a computer network. DHCP allows client devices to seamlessly join a network, receive an address, and start communicating. Without DHCP, users would have to manually choose an address an ensure no other user was using the same address. DHCP uses a client/server architecture. When a client joins a network, it will broadcast a "DHCP Discover" message. One or more DHCP servers will receive the broadcast and send back a "DHCP Offer". The server is responsible for keeping track of available IP addresses, and the offer will contain an IP address along with other configuration options. The client will accept one of the offers it receives and can now use that address to communicate on the network.

On Unix operating systems, the `dhclient` command provides methods for automating the process of requesting an address and configuring a network interface to use it. `dhclient` includes a hook system to allow other programs to register callbacks for when a DHCP offer is accepted or an address is released. On Ubuntu 12.04, the `/etc/dhcp/dhclient-enter-hooks.d` and `/etc/dhcp/dhclient-exit-hooks.d` directories contain the scripts to be automatically executed by the hooks. Each script is automatically executed using Bash and the details of the DHCP offer are stored in environment variables. This feature allows seamlessly connecting to a network but creates the potential for security vulnerabilities.



# Exploiting FTP

# Conclusion
- Base vulnerability not very interesting, no priviledge escalation
- SSH vulnerability is high severity but isn't widely used
- Key takeaways about protecting against injection vulnerabilities
- Interesting that none of these programs choose to validate the contents of environment variables