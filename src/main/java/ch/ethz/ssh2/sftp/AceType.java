package ch.ethz.ssh2.sftp;

/**
 * @version $Id$
 */
public final class AceType {

    private AceType() {
    }

    private static final int ACE4_ACCESS_ALLOWED_ACE_TYPE = 0x00000000;
    private static final int ACE4_ACCESS_DENIED_ACE_TYPE = 0x00000001;
    private static final int ACE4_SYSTEM_AUDIT_ACE_TYPE = 0x00000002;
    private static final int ACE4_SYSTEM_ALARM_ACE_TYPE = 0x00000003;

}
