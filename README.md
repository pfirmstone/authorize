# authorize
An Authorization Delegation Layer for Java, a compatibility layer to support Authorization on multiple versions of Java.

All we really need to do here is to capture doPrivileged calls.

How should be capture the AccessControlContext for use in doPrivileged calls?   We can't capture AccessControlContext in Thread's inherited context. I suspect that we need to use AccessControlContext to encapsulate Authorization from HPS.
