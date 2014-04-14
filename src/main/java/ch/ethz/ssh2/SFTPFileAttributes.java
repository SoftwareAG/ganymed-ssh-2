package ch.ethz.ssh2;

/**
 * @version $Id$
 */
public interface SFTPFileAttributes {

    boolean isDirectory();

    boolean isRegularFile();

    boolean isSymlink();

    byte[] toBytes();
}
