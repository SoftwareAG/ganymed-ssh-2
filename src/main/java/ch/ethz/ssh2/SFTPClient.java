package ch.ethz.ssh2;

import java.io.IOException;
import java.util.List;

/**
 * @version $Id$
 */
public interface SFTPClient {

    /**
     * Retrieve the file attributes of an open file.
     *
     * @param handle a SFTPv3FileHandle handle.
     * @return a SFTPv3FileAttributes object.
     * @throws IOException
     */
    SFTPFileAttributes fstat(SFTPFileHandle handle) throws IOException;

    /**
     * Retrieve the file attributes of a file. This method
     * follows symbolic links on the server.
     *
     * @param path See the {@link SFTPClient comment} for the class for more details.
     * @return a SFTPv3FileAttributes object.
     * @throws IOException
     * @see #lstat(String)
     */
    SFTPFileAttributes stat(String path) throws IOException;

    /**
     * Retrieve the file attributes of a file. This method
     * does NOT follow symbolic links on the server.
     *
     * @param path See the {@link SFTPClient comment} for the class for more details.
     * @return a SFTPv3FileAttributes object.
     * @throws IOException
     * @see #stat(String)
     */
    SFTPFileAttributes lstat(String path) throws IOException;

    /**
     * Read the target of a symbolic link. Note: OpenSSH (as of version 4.4) gets very upset
     * (SSH_FX_BAD_MESSAGE error) if you want to read the target of a file that is not a
     * symbolic link. Better check first with {@link #lstat(String)}.
     *
     * @param path See the {@link SFTPClient comment} for the class for more details.
     * @return The target of the link.
     * @throws IOException
     */
    String readLink(String path) throws IOException;

    /**
     * Modify the attributes of a file. Used for operations such as changing
     * the ownership, permissions or access times, as well as for truncating a file.
     *
     * @param path See the {@link SFTPClient comment} for the class for more details.
     * @param attr A SFTPv3FileAttributes object. Specifies the modifications to be
     *             made to the attributes of the file. Empty fields will be ignored.
     * @throws IOException
     */
    void setstat(String path, SFTPFileAttributes attr) throws IOException;

    /**
     * Modify the attributes of a file. Used for operations such as changing
     * the ownership, permissions or access times, as well as for truncating a file.
     *
     * @param handle a SFTPv3FileHandle handle
     * @param attr   A SFTPv3FileAttributes object. Specifies the modifications to be
     *               made to the attributes of the file. Empty fields will be ignored.
     * @throws IOException
     */
    void fsetstat(SFTPFileHandle handle, SFTPFileAttributes attr) throws IOException;

    /**
     * Create a symbolic link on the server. Creates a link "src" that points
     * to "target".
     *
     * @param src    See the {@link SFTPClient comment} for the class for more details.
     * @param target See the {@link SFTPClient comment} for the class for more details.
     * @throws IOException
     */
    void createSymlink(String src, String target) throws IOException;

    /**
     * Create a symbolic link on the server. Creates a link "src" that points
     * to "target".
     *
     * @param src    See the {@link SFTPClient comment} for the class for more details.
     * @param target See the {@link SFTPClient comment} for the class for more details.
     * @throws IOException
     */
    void createHardlink(String src, String target) throws IOException;

    /**
     * Have the server canonicalize any given path name to an absolute path.
     * This is useful for converting path names containing ".." components or
     * relative pathnames without a leading slash into absolute paths.
     *
     * @param path See the {@link SFTPClient comment} for the class for more details.
     * @return An absolute path.
     * @throws IOException
     */
    String canonicalPath(String path) throws IOException;

    void setCharset(String charset) throws IOException;

    String getCharset();

    SFTPFileHandle openDirectory(String path) throws IOException;

    boolean isConnected();

    void close();

    List<? extends SFTPDirectoryEntry> ls(String dirName) throws IOException;

    /**
     * Create a new directory.
     *
     * @param name             See the {@link SFTPClient comment} for the class for more details.
     * @param posixPermissions the permissions for this directory, e.g., "0700" (remember that
     *                         this is octal noation). The server will likely apply a umask.
     * @throws IOException
     */
    void mkdir(String name, int posixPermissions) throws IOException;

    /**
     * Remove a file.
     *
     * @param filename See the {@link SFTPClient comment} for the class for more details.
     * @throws IOException
     */
    void rm(String filename) throws IOException;

    /**
     * Remove an empty directory.
     *
     * @param dirName See the {@link SFTPClient comment} for the class for more details.
     * @throws IOException
     */
    void rmdir(String dirName) throws IOException;

    /**
     * Move a file or directory.
     *
     * @param oldPath See the {@link SFTPClient comment} for the class for more details.
     * @param newPath See the {@link SFTPClient comment} for the class for more details.
     * @throws IOException
     */
    void mv(String oldPath, String newPath) throws IOException;

    /**
     * Create a file and open it for reading and writing.
     * Same as {@link #createFile(String, SFTPFileAttributes) createFile(filename, null)}.
     *
     * @param filename See the {@link SFTPClient comment} for the class for more details.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    SFTPFileHandle createFile(String filename) throws IOException;

    /**
     * Create a file and open it for reading and writing.
     * You can specify the default attributes of the file (the server may or may
     * not respect your wishes).
     *
     * @param filename See the {@link SFTPv3Client comment} for the class for more details.
     * @param attr     may be <code>null</code> to use server defaults. Probably only
     *                 the <code>uid</code>, <code>gid</code> and <code>permissions</code>
     *                 (remember the server may apply a umask) entries of the {@link SFTPv3FileHandle}
     *                 structure make sense. You need only to set those fields where you want
     *                 to override the server's defaults.
     * @return a SFTPv3FileHandle handle
     * @throws IOException
     */
    SFTPFileHandle createFile(String filename, SFTPFileAttributes attr) throws IOException;

    SFTPFileHandle openFile(String filename, int flags) throws IOException;

    /**
     * Read bytes from a file in a parallel fashion. As many bytes as you want will be read.
     * <p/>
     * <ul>
     * <li>The server will read as many bytes as it can from the file (up to <code>len</code>),
     * and return them.</li>
     * <li>If EOF is encountered before reading any data, <code>-1</code> is returned.
     * <li>If an error occurs, an exception is thrown</li>.
     * <li>For normal disk files, it is guaranteed that the server will return the specified
     * number of bytes, or up to end of file. For, e.g., device files this may return
     * fewer bytes than requested.</li>
     * </ul>
     *
     * @param handle     a SFTPv3FileHandle handle
     * @param fileOffset offset (in bytes) in the file
     * @param dst        the destination byte array
     * @param dstoff     offset in the destination byte array
     * @param len        how many bytes to read, 0 &lt; len
     * @return the number of bytes that could be read, may be less than requested if
     * the end of the file is reached, -1 is returned in case of <code>EOF</code>
     * @throws IOException
     */
    int read(SFTPFileHandle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException;

    /**
     * Write bytes to a file. If <code>len</code> &gt; 32768, then the write operation will
     * be split into multiple writes.
     *
     * @param handle     a SFTPv3FileHandle handle.
     * @param fileOffset offset (in bytes) in the file.
     * @param src        the source byte array.
     * @param srcoff     offset in the source byte array.
     * @param len        how many bytes to write.
     * @throws IOException
     */
    void write(SFTPFileHandle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException;

    /**
     * Close a file.
     *
     * @param handle a file handle
     * @throws IOException
     */
    void closeFile(SFTPFileHandle handle) throws IOException;
}
