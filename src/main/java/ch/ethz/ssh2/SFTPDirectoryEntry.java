package ch.ethz.ssh2;

/**
 * @version $Id$
 */
public interface SFTPDirectoryEntry {

    public String getFilename();

    public SFTPFileAttributes getAttributes();

}
