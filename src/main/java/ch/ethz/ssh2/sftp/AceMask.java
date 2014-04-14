package ch.ethz.ssh2.sftp;

/**
 * @version $Id$
 */
public final class AceMask {
    private AceMask() {
    }

    public static final int ACE4_READ_DATA = 0x00000001;
    public static final int ACE4_LIST_DIRECTORY = 0x00000001;
    public static final int ACE4_WRITE_DATA = 0x00000002;
    public static final int ACE4_ADD_FILE = 0x00000002;
    public static final int ACE4_APPEND_DATA = 0x00000004;
    public static final int ACE4_ADD_SUBDIRECTORY = 0x00000004;
    public static final int ACE4_READ_NAMED_ATTRS = 0x00000008;
    public static final int ACE4_WRITE_NAMED_ATTRS = 0x00000010;
    public static final int ACE4_EXECUTE = 0x00000020;
    public static final int ACE4_DELETE_CHILD = 0x00000040;
    public static final int ACE4_READ_ATTRIBUTES = 0x00000080;
    public static final int ACE4_WRITE_ATTRIBUTES = 0x00000100;
    public static final int ACE4_DELETE = 0x00010000;
    public static final int ACE4_READ_ACL = 0x00020000;
    public static final int ACE4_WRITE_ACL = 0x00040000;
    public static final int ACE4_WRITE_OWNER = 0x00080000;
    public static final int ACE4_SYNCHRONIZE = 0x00100000;

}
