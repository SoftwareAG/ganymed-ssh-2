package ch.ethz.ssh2.sftp;

/**
 * @version $Id$
 */
public final class AclFlags {

    /**
     * If INCLUDED is set during a setstat operation, then the client
     * intends to modify the ALLOWED/DENIED entries of the ACL.
     * Otherwise, the client intends for these entries to be
     * preserved.
     */
    public static final int SFX_ACL_CONTROL_INCLUDED = 0x00000001;
    /**
     * If the PRESENT bit is not set, then the client wishes to remove
     * control entries.  If the server doesn't support separate
     * control and audit information, the client MUST not clear this
     * bit without also clearing the AUDIT_ALARM_PRESENT bit.
     */
    public static final int SFX_ACL_CONTROL_PRESENT = 0x00000002;
    /**
     * If INHERITED is set, then ALLOW/DENY ACEs MAY be inherited from
     * the parent directory.  If it is off, then they MUST not be
     * INHERITED.  If the server does not support controlling
     * inheritance, then the client MUST clear this bit; in this case
     * the inheritance properties of the server are undefined.
     */
    public static final int SFX_ACL_CONTROL_INHERITED = 0x00000004;
    /**
     * If INCLUDE is set during a setstat operation, then the client
     * intends to modify the AUDIT/ALARM entries of the ACL.
     * Otherwise, the client intends for these entries to be
     * preserved.
     */
    public static final int SFX_ACL_AUDIT_ALARM_INCLUDED = 0x00000010;
    /**
     * If INHERITED is set, then AUDIT/ALARM ACEs MAY be inherited
     * from the parent directory.  If it is off, then they MUST not be
     * INHERITED.  If the server does not support controlling
     * inheritance, then the client MUST clear this bit; in this case
     * the inheritance properties of the server are undefined.
     */
    public static final int SFX_ACL_AUDIT_ALARM_INHERITED = 0x00000020;
}
