/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package au.net.zeus.authorize;

import java.security.ProtectionDomain;

/**
 * {@code DomainCombiner} is used to update and optimize {@code
 * ProtectionDomain}s from an {@code AccessControlContext}.
 * 
 * @see AccessControlContext
 * @see AccessControlContext#AccessControlContext(AccessControlContext,
 *      DomainCombiner)
 */
public interface DomainCombiner {

    /**
     * Returns a combination of the two provided {@code ProtectionDomain}
     * arrays. Implementers can simply merge the two arrays into one, remove
     * duplicates and perform other optimizations.
     *
     * @param current
     *            the protection domains of the current execution thread (since
     *            the most recent call to {@link AccessController#doPrivileged}
     *            ).
     * @param assigned
     *            the protection domains of the parent thread, maybe {@code
     *            null}.
     * @return a single {@code ProtectionDomain} array computed from the two
     *         provided arrays.
     */
    ProtectionDomain[] combine(ProtectionDomain[] current,
            ProtectionDomain[] assigned);
}
