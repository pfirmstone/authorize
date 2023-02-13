# authorize
An Authorization Delegation Layer for Java, a compatibility layer to support Authorization on multiple versions of Java, to assist with transition from SecurityManager to the High Performance Security Authorization Library (HPS).

All we really need to do here is to capture doPrivileged calls.

How should be capture the AccessControlContext for use in doPrivileged calls?   We can't capture AccessControlContext in Thread's inherited context. I suspect that we need to use AccessControlContext to encapsulate Authorization from HPS.

One of challenges we have, is supporting multiple versions of Java, for Java 8, we could simply encapsulate the existing SecurityManager framework.  HPS is fundamentally different, while doPrivileged calls are fundamentally the same, the stack walk and guards are different.  It will require two different implementation of HPS to support Java 8, in addition to later versions of Java.

It would be preferable to have OpenJDK retain AccessController and AccessControlContext, as zero OP's, so we can use doPrivileged calls in existing software, without the need to create a compatibility layer.
