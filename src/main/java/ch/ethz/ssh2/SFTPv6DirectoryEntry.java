package ch.ethz.ssh2;

/**
 * @version $Id$
 */
public class SFTPv6DirectoryEntry implements SFTPDirectoryEntry {
    /**
     * A relative name within the directory, without any path components.
     */
    public String filename;

    /**
     * The attributes of this entry.
     */
    public SFTPv6FileAttributes attributes;

    public String getFilename() {
        return filename;
    }

    public SFTPv6FileAttributes getAttributes() {
        return attributes;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("SFTPv6DirectoryEntry{");
        sb.append("filename='").append(filename).append('\'');
        sb.append(", attributes=").append(attributes);
        sb.append('}');
        return sb.toString();
    }
}
