/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package au.net.zeus.authorize;

import java.security.CodeSource;
import java.security.PermissionCollection;

/**
 *
 * @author peter
 */
public abstract class PolicySPI {
    
    public abstract PermissionCollection getPermissions(CodeSource cs);
    
}
