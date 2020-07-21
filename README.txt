This repository is forked from one of the automatic exports of code.google.com/p/ganymed-ssh-2 and contains updates on top of the ganymed-ssh2-262 tag. The ganymed-ssh2-262 tag was used to produce the latest public build in Maven Central, which is version 262, so builds from this repository should be version 263. The latest public build in Maven Central is available at https://search.maven.org/artifact/ch.ethz.ganymed/ganymed-ssh2/262/jar
The following features were added in version 263:
- Gradle build support.
- OSGi support.
- Message authentication: support for hmac-sha2-256 and hmac-sha2-512.
- Key exchange: support for diffie-hellman-group14-sha256, diffie-hellman-group16-sha512, and diffie-hellman-group18-sha512.

The code from this repository is used in Software AG Command Central and tested using the Command Central continuous integration. However, this code is not officially supported by Software AG. 


**********************************

This software is provided as-is and without warranty or support. It does not constitute part of the Software AG product suite. Users are free to use, fork and modify it, subject to the license agreement. While Software AG welcomes contributions, we cannot guarantee to include every contribution in the master project.

**********************************




Original content:




Ganymed SSH-2 for Java - build 261
==================================

https://code.google.com/p/ganymed-ssh-2/

Ganymed SSH-2 for Java is a library which implements the SSH-2 protocol in pure Java
(tested on J2SE 5 and 6). It allows one to connect to SSH servers from within
Java programs. It supports SSH sessions (remote command execution and shell access),
local and remote port forwarding, local stream forwarding, X11 forwarding, SCP and SFTP.
There are no dependencies on any JCE provider, as all crypto functionality is included.

There is also a basic (preliminary) SSH server implementation included.

Ganymed SSH-2 for Java was originally developed by Christian Plattner for the Ganymed
replication project and a couple of other projects at the IKS group at ETH Zurich (Switzerland).

These days, the code is maintained by Dr. Christian Plattner and David Kocher.

This distribution contains the source code, examples, javadoc and the FAQ.
It also includes a pre-compiled jar version of the library which is ready to use.

- Please read the included LICENCE.txt
- Latest changes can be found in HISTORY.txt
- The FAQ can be found in the FAQ.html

Switzerland, August 2013
