/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package au.net.zeus.authorize;

import java.security.Guard;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;

/**
 * An AccessControlContext encapsulates the information which is needed by class
 * AccessController to detect if a Permission would be granted at a particular
 * point in a programs execution.
 */
public final class AccessControlContext {
    
    private static boolean implies(ProtectionDomain domain, Guard g){
        Policy policy = Policy.getAccessiblePolicy();
        if (policy != null) return policy.implies(domain, getDomainCombiner);
        return domain.implies(getDomainCombiner);
    }
    
    private static ProtectionDomain[] checkNullThenCompact(ProtectionDomain[] context) throws NullPointerException{
        if (context == null) throw new NullPointerException("Context cannot be null");
        int length = context.length;
        int domainIndex = 0;
        ProtectionDomain [] domainsArray = new ProtectionDomain[length];
        next: for (int i = 0; i < length; i++) {
                ProtectionDomain current = context[i];
                for (int j = 0; j < i; j++)
                        if (current == domainsArray[j])
                                continue next;
                domainsArray[domainIndex++] = current;
        }
        if (domainIndex != length) {
                ProtectionDomain[] copy = new ProtectionDomain[domainIndex];
                System.arraycopy(domainsArray, 0, copy, 0, domainIndex);
                domainsArray = copy;
        }
        return domainsArray;
    }
    
    private static boolean checkGuard(Guard g) throws SecurityException {
        g.checkGuard(null);
        return true;
    }
    
   
    final DomainCombiner domainCombiner;

    final ProtectionDomain[] domainsArray;
    
    private final int hashCode;

    private static final SecurityPermission createAccessControlContext = new SecurityPermission(
                    "createAccessControlContext");

    private static final SecurityPermission getDomainCombiner = new SecurityPermission(
                    "getDomainCombiner");

    /**
     * Constructs a new instance of this class given an array of protection
     * domains.
     * 
     */
    public AccessControlContext(ProtectionDomain[] context) {
            this(checkNullThenCompact(context), null, false);
    }
    
    /**
     * Constructs a new instance of this class given a context and a
     * DomainCombiner
     */
    public AccessControlContext(AccessControlContext acc, DomainCombiner combiner) {
        this(acc.domainsArray, combiner, checkGuard(createAccessControlContext));
    }
    
    AccessControlContext(ProtectionDomain[] context, 
                                    DomainCombiner combiner,
                                    boolean checkGuard)
    {
        this.domainsArray = context;
        this.domainCombiner = combiner;
        int result = 0;
        int i = domainsArray.length;
        while (--i >= 0)
                result ^= domainsArray[i].hashCode();
        this.hashCode = result;
    }
    
    /**
     * Checks if the permission <code>perm</code> is allowed in this context.
     * All ProtectionDomains must grant the permission for it to be granted.
     * 
     * @param perm
     *            java.security.Permission the permission to check
     * @exception AccessControlException
     *                thrown when perm is not granted.
     */
    public void checkPermission(Permission perm) throws SecurityException {
            if (perm == null)
                    throw new NullPointerException();
            int i = domainsArray.length;
            while (--i >= 0 && implies(domainsArray[i],perm)){}
            if (i >= 0) {
                throw new AccessControlException("Access Denied", perm);
            }
    }

    /**
     * Compares the argument to the receiver, and answers true if they represent
     * the <em>same</em> object using a class specific comparison. In this
     * case, they must both be AccessControlContexts and contain the same
     * protection domains.
     * 
     * 
     * @param o
     *            the object to compare with this object
     * @return <code>true</code> if the object is the same as this object
     *         <code>false</code> if it is different from this object
     * @see #hashCode
     */
    @Override
    public boolean equals(Object o) {
            if (this == o)
                    return true;
            if (o == null || this.getClass() != o.getClass())
                    return false;
            AccessControlContext otherContext = (AccessControlContext) o;
            ProtectionDomain[] otherDomains = otherContext.domainsArray;
            int length = domainsArray.length;
            if (length != otherDomains.length)
                    return false;

            next: for (int i = 0; i < length; i++) {
                    ProtectionDomain current = domainsArray[i];
                    for (int j = 0; j < length; j++)
                            if (current == otherDomains[j])
                                    continue next;
                    return false;
            }
            return true;
    }

    /**
     * Answers an integer hash code for the receiver. Any two objects which
     * answer <code>true</code> when passed to <code>equals</code> must
     * answer the same value for this method.
     * 
     * 
     * @return the receiver's hash
     * 
     * @see #equals
     */
    @Override
    public int hashCode() {
            return hashCode;
    }

    /**
     * Answers the DomainCombiner for the receiver.
     * 
     */
    public DomainCombiner getDomainCombiner() {
            SecurityManager security = System.getSecurityManager();
            if (security != null)
                    security.checkPermission(getDomainCombiner);
            return domainCombiner;
    }

}
