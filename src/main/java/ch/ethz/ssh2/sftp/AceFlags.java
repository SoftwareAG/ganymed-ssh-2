package ch.ethz.ssh2.sftp;

/**
 * @version $Id$
 */
public final class AceFlags {
    private AceFlags() {
    }

    public static final int ACE4_FILE_INHERIT_ACE = 0x00000001;
    public static final int ACE4_DIRECTORY_INHERIT_ACE = 0x00000002;
    public static final int ACE4_NO_PROPAGATE_INHERIT_ACE = 0x00000004;
    public static final int ACE4_INHERIT_ONLY_ACE = 0x00000008;
    public static final int ACE4_SUCCESSFUL_ACCESS_ACE_FLAG = 0x00000010;
    public static final int ACE4_FAILED_ACCESS_ACE_FLAG = 0x00000020;
    public static final int ACE4_IDENTIFIER_GROUP = 0x00000040;
}
