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

/**
 * {@code AccessControlException} is thrown when authorization has been rejected
 * by a guard.
 */
public class AccessControlException extends SecurityException {
    private static final long serialVersionUID = 1;

    private final Guard guard;
    
    /**
    * Constructs a new instance of {@code AccessControlException} with the
    * given message and the requested {@code Permission} which was not granted.
    *
    * @param reason the detail reason for the exception.
    * @param g the {@code Guard} who rejected authorization.
    */
    public AccessControlException(String reason, Guard g){
        super(reason);
        this.guard = g;
    }
    
    /**
     * Returns the Guard that took exception.
     * 
     * @return Guard who rejected authorization.
     */
    public Guard guard(){
        return guard;
    }
    
}
